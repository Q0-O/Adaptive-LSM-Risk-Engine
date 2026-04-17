#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/capability.h>

#define RATE_LIMIT_NS_DEFAULT 10000000ULL
#define BEHAVIOR_DECAY_NS     5000000000ULL  
#define BEHAVIOR_MIN_COUNT    3
#define RISK_THRESHOLD        80

/* ================= TRACE FLAGS ================= */
#define TRACE_PRIV          (1U << 0)
#define TRACE_POLICY_HIT    (1U << 1)
#define TRACE_DEFAULT       (1U << 2)
#define TRACE_EXEC_OP       (1U << 3)
#define TRACE_ID_FAIL       (1U << 4)

/* ================= DECISION REASONS ================= */
#define REASON_PRIV_BYPASS      1
#define REASON_POLICY_EXACT     2
#define REASON_POLICY_CGROUP    3
#define REASON_POLICY_UID       4
#define REASON_DEFAULT_DENY     5
#define REASON_RATE_LIMIT       6
#define REASON_ID_FAIL          7
#define REASON_BEHAVIOR_STALE   8

/* ================= KEYS ================= */
struct file_key {
    u64 inode;
    u32 dev;
} __attribute__((packed));

struct policy_key {
    u64 inode;
    u32 dev;
    u32 uid;
    u64 cgroup_id;
    u32 op;
} __attribute__((packed));

struct rate_key {
    u32 uid;
    u64 cgroup_id;
    u32 op;
} __attribute__((packed));

struct behavior_key {
    u32 uid;
    u64 inode;
    u32 op;
} __attribute__((packed));

struct behavior_val {
    u64 count;
    u64 last_seen;
} __attribute__((packed));

struct global_config {
    u32 enforce;
    u32 default_deny;
    u32 audit_mode;
    u32 rate_limit_ns;
    u32 risk_threshold;
} __attribute__((packed));

struct security_ctx {
    struct file_key fk;
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    u32 op;
    bool privileged;
    u32 trace;
    int decision_reason;
};

/* ================= MAPS ================= */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct policy_key);
    __type(value, u8);
} policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u8);
} uid_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rate_key);
    __type(value, u64);
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct behavior_key);
    __type(value, struct behavior_val);
} behavior_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct global_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* ================= HELPERS ================= */
static __always_inline struct global_config *get_cfg(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

static __always_inline bool is_privileged(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) return false;
    const struct cred *cred = BPF_CORE_READ(task, cred);
    if (!cred) return false;
    u64 cap0 = BPF_CORE_READ(cred, cap_effective.cap[0]);
    u64 cap1 = BPF_CORE_READ(cred, cap_effective.cap[1]);
    return (cap0 | (cap1 << 32)) & (1ULL << CAP_SYS_ADMIN);
}

static __always_inline bool extract_file(struct file *f, struct file_key *fk)
{
    if (!f) return false;
    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode || !inode->i_sb) return false;
    fk->inode = BPF_CORE_READ(inode, i_ino);
    fk->dev   = BPF_CORE_READ(inode, i_sb, s_dev);
    return fk->inode && fk->dev;
}

static __always_inline bool extract_inode(struct inode *inode, struct file_key *fk)
{
    if (!inode || !inode->i_sb) return false;
    fk->inode = BPF_CORE_READ(inode, i_ino);
    fk->dev   = BPF_CORE_READ(inode, i_sb, s_dev);
    return fk->inode && fk->dev;
}

static __always_inline void emit_event(struct security_ctx *ctx, int decision)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    e->ts        = bpf_ktime_get_ns();
    e->pid       = ctx->pid;
    e->uid       = ctx->uid;
    e->inode     = ctx->fk.inode;
    e->dev       = ctx->fk.dev;
    e->op        = ctx->op;
    e->cgroup_id = ctx->cgroup_id;
    e->decision  = decision;
    e->trace     = ctx->trace;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->path[0]   = '\0';
    bpf_ringbuf_submit(e, 0);
}

/* ================= ADAPTIVE RISK SCORING ENGINE ================= */
static __always_inline int evaluate_security(struct security_ctx *ctx, struct global_config *cfg)
{
    int risk = 0;
    u64 now = bpf_ktime_get_ns();

    if (ctx->privileged) {
        ctx->trace |= TRACE_PRIV;
        ctx->decision_reason = REASON_PRIV_BYPASS;
        return 0;
    }

    /* 1. Rate Limit */
    struct rate_key rk = { .uid = ctx->uid, .cgroup_id = ctx->cgroup_id, .op = ctx->op };
    u64 *last = bpf_map_lookup_elem(&rate_limit, &rk);
    if (last && (now - *last) < cfg->rate_limit_ns) {
        risk += 30;
        ctx->decision_reason = REASON_RATE_LIMIT;
    }
    bpf_map_update_elem(&rate_limit, &rk, &now, BPF_ANY);

    /* 2. Policy Risk */
    struct policy_key pk = {
        .inode = ctx->fk.inode, .dev = ctx->fk.dev,
        .uid = ctx->uid, .cgroup_id = ctx->cgroup_id, .op = ctx->op
    };
    u8 *exact = bpf_map_lookup_elem(&policy, &pk);
    if (exact) {
        ctx->trace |= TRACE_POLICY_HIT;
        ctx->decision_reason = REASON_POLICY_EXACT;
        risk += *exact ? 100 : 0;
    } else {
        struct policy_key cg_key = { .cgroup_id = ctx->cgroup_id, .op = ctx->op };
        u8 *cg = bpf_map_lookup_elem(&policy, &cg_key);
        if (cg) {
            ctx->trace |= TRACE_POLICY_HIT;
            ctx->decision_reason = REASON_POLICY_CGROUP;
            risk += *cg ? 70 : 0;
        } else {
            u8 *uact = bpf_map_lookup_elem(&uid_policy, &ctx->uid);
            if (uact) {
                ctx->trace |= TRACE_POLICY_HIT;
                ctx->decision_reason = REASON_POLICY_UID;
                risk += *uact ? 50 : 0;
            }
        }
    }

    /* 3. Behavior Trust Engine */
    struct behavior_key bk = { .uid = ctx->uid, .inode = ctx->fk.inode, .op = ctx->op };
    struct behavior_val *val = bpf_map_lookup_elem(&behavior_map, &bk);

    if (val) {
        if ((now - val->last_seen) > BEHAVIOR_DECAY_NS) {
            /* Stale → reset */
            val->count = 1;
            val->last_seen = now;
            risk += 40;
            ctx->decision_reason = REASON_BEHAVIOR_STALE;
        } else {
            val->count++;
            val->last_seen = now;
            if (val->count >= BEHAVIOR_MIN_COUNT) {
                risk -= 20;                    // Trusted behavior
            } else {
                risk += 40;                    // Still learning
                ctx->decision_reason = REASON_BEHAVIOR_STALE;
            }
        }
    } else {
        /* Cold-start */
        struct behavior_val new_val = { .count = 1, .last_seen = now };
        bpf_map_update_elem(&behavior_map, &bk, &new_val, BPF_ANY);
        risk += 40;
        ctx->decision_reason = REASON_BEHAVIOR_STALE;
    }

    /* Final Decision */
    if (risk >= cfg->risk_threshold || (cfg->default_deny && risk > 0)) {
        ctx->trace |= TRACE_DEFAULT;
        return -EACCES;
    }

    return 0;
}

/* ================= HANDLERS ================= */
static __always_inline int handle_file(struct file *f, u32 op, bool is_exec)
{
    struct global_config *cfg = get_cfg();
    if (!cfg) return 0;

    struct security_ctx ctx = {};
    ctx.op = op;
    ctx.pid = bpf_get_current_pid_tgid() >> 32;

    if (!extract_file(f, &ctx.fk)) {
        ctx.trace |= TRACE_ID_FAIL;
        ctx.decision_reason = REASON_ID_FAIL;
        return 0;
    }

    ctx.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ctx.cgroup_id  = bpf_get_current_cgroup_id();
    ctx.privileged = is_privileged();
    if (is_exec) ctx.trace |= TRACE_EXEC_OP;

    int decision = evaluate_security(&ctx, cfg);

    if (decision != 0 || ctx.privileged ||
        (cfg->audit_mode && (bpf_get_prandom_u32() & 15) == 0))
        emit_event(&ctx, decision);

    if (cfg->enforce && decision != 0)
        return -EACCES;

    return decision;
}

SEC("lsm.s/inode_permission")
int inode_perm(struct inode *inode, int mask)
{
    struct global_config *cfg = get_cfg();
    if (!cfg) return 0;

    struct security_ctx ctx = {};
    ctx.op = 2;
    ctx.pid = bpf_get_current_pid_tgid() >> 32;

    if (!extract_inode(inode, &ctx.fk)) {
        ctx.trace |= TRACE_ID_FAIL;
        ctx.decision_reason = REASON_ID_FAIL;
        return 0;
    }

    ctx.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ctx.cgroup_id  = bpf_get_current_cgroup_id();
    ctx.privileged = is_privileged();

    int decision = evaluate_security(&ctx, cfg);

    if (decision != 0 || ctx.privileged ||
        (cfg->audit_mode && (bpf_get_prandom_u32() & 15) == 0))
        emit_event(&ctx, decision);

    if (cfg->enforce && decision != 0)
        return -EACCES;

    return decision;
}

SEC("lsm.s/file_open")
int file_open(struct file *f, int flags)
{
    return handle_file(f, 0, false);
}

SEC("lsm.s/bprm_check_security")
int exec_check(struct linux_binprm *bprm)
{
    if (!bprm || !bprm->file) return 0;
    return handle_file(bprm->file, 1, true);
}

char LICENSE[] SEC("license") = "GPL";
