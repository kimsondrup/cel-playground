# k8s/oracle — differential-testing oracle

Answers "what would a real cluster actually do with this policy and this object?"
so the playground's vap, map and webhook modes can be checked against ground
truth rather than against our reading of the apiserver source.

There are two oracles here, and the cheap one is the one you want.

**In-process oracle** (`inprocess.go`, `mapinprocess.go`) reproduces upstream's
unexported `validating.compilePolicy` and `mutating.compilePolicy` out of
exported API, then calls upstream's own `validating.Validator` and
`patch.Patcher`. No etcd, no apiserver, no network — but the exact
evaluation code path a cluster takes once a policy is admitted and matched. It
runs in milliseconds and it is the only way to get **exact CEL costs**, which
a real apiserver never reports.

**Cluster oracle** (`harness.go`, `cluster.go`, `webhookserver.go`) starts a real
`kube-apiserver` + `etcd` via controller-runtime's envtest. Use it for the
things the in-process oracle structurally cannot answer: registry validation
(what the apiserver refuses to *store*), served apiVersions, and whether a
webhook's `matchConditions` cause the apiserver to actually dial the webhook.

## Why this is a separate Go module

`k8s.io/apiserver/pkg/admission/plugin/policy/validating` and
controller-runtime drag in grpc, konnectivity, OTLP and apiextensions. The root
module is compiled to wasm and is kept lean. A nested module is excluded from
the parent's `./...`, so the repo's own `go test ./...` never sees this
directory and the root `go.mod`/`go.sum` stay byte-identical.

Every file also carries `//go:build oracle`, so even building this module
without the tag yields no packages.

## One-time setup

Assets live outside the repo (they are ~166 MB and the worktree volume is
nearly full):

```sh
go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest \
    use 1.36.2 --bin-dir ~/.local/share/kubebuilder-envtest -p path
```

Pick the version that matches `k8s.io/apiserver` in the root `go.mod`
(currently v0.36.2 → envtest 1.36.2); `AssetsDir` will only use assets of that
minor, so downloading a newer set alongside them changes nothing. `-p path`
just prints where they landed — nothing consumes it. `setup-envtest list` shows
what is available.

## Running

```sh
make test-oracle          # from the repo root
cd k8s/oracle && go test -tags oracle ./... -v
```

Without `-tags oracle` the module has no packages and the command is a no-op.
Without the envtest assets the cluster-backed tests skip with a reason and the
in-process tests still run — so the suite degrades rather than failing on a
machine that has never downloaded the binaries.

Useful subsets:

```sh
go test -tags oracle -run TestInProcess       ./... -v   # no cluster, ~0.5s
go test -tags oracle -run TestAcceptance      ./... -v   # registry validation + discovery
go test -tags oracle -run TestWebhook         ./... -v   # real webhook invocation
go test -tags oracle -run TestCost            ./... -v   # cost budget behaviour, ~25s
go test -tags oracle -run TestPlaygroundVsUpstream ./... -v  # the differential test
go test -tags oracle -run TestWebhookParityWithUpstream ./... -v  # webhook matchConditions vs a cluster
go test -tags oracle -run TestMAPPlaygroundMatchesUpstream ./... -v  # the map corpus vs upstream's patchers
go test -tags oracle -run TestMAPPlaygroundMatchesCluster  ./... -v  # the map corpus vs a real apiserver
```

## The mutating mode

`TestMAPPlaygroundMatchesUpstream` runs every `k8s/testdata/map` fixture through
`k8s.EvalMutatingAdmissionPolicy` and through upstream's own patchers, and
compares the object each produced and what each mutation was charged. The two
reproduce `mutating.compilePolicy` independently and take their merge schema
from different places -- the binary embeds a copy, the oracle reads client-go's
live one -- so agreeing on every fixture is what says the copy is faithful.

`TestMAPPlaygroundMatchesCluster` submits five of them to a real apiserver as a
dry-run CREATE, twice: once with the policy bound and once without. The paths
where the two answers differ are the policy's doing and nothing else's. The
cluster also defaults the object, which the playground does not, so its answer
has to be *contained in* the cluster's rather than equal to it -- with lists
held to the same length and order, which is what makes a keyed list merged
wrongly a failure rather than a subset.

`TestBuiltinSchemaIsCurrent` generates the two files the wasm binary embeds:

```sh
go test -tags oracle -run TestBuiltinSchemaIsCurrent ./... -update-builtins
```

It fails when client-go's generated merge schema moves, which is the only thing
standing between the embedded copy and silent rot.

`TestWebhookParityWithUpstream` is the webhook half of the differential test. It
drives the repo's own `k8s/testdata/webhook` fixtures through `k8s.EvalWebhook`,
turns the per-condition results into the call/skip/reject decision upstream's
`matchconditions.(*matcher).Match` would make, and checks it against a cluster
that was handed the same configuration and object. The fixtures' RBAC tab is
created on the cluster for real and the request is made as the user the request
tab names, via impersonation from the envtest admin's `system:masters` — so the
apiserver's own RBAC authorizer, not a simulation of it, answers
`authorizer...check("breakglass").allowed()`.

Each fixture webhook is registered three times: as itself, as a
matchCondition-free twin with identical rules, and alongside one catch-all. The
twin separates "the matchConditions said no" from "the rules never matched this
object", and the catch-all is the per-request proof that the configuration was
live — without them a webhook that is never dialled looks like a pass.

Timings on this machine: control plane start ~2.0–2.5 s (once per package, shared
via `TestMain`); each VAP case ~1 s, dominated by waiting for the admission
plugin's informer to observe the new policy; `TestCostBudgetBisect` ~22 s
because it drives two admission requests that each burn ~10 M CEL cost.

## How policy readiness is handled

A policy that was just created is not yet enforcing: the admission plugin
compiles policies off a shared informer. Polling the object under test cannot
close that window, because "allowed" is indistinguishable from "not yet
loaded".

`Oracle.WaitPoliciesActive` installs a throwaway marker policy that denies one
labelled ConfigMap and polls until that denial is observed. Both informers
deliver in resourceVersion order and the plugin recompiles from a single store
snapshot, so a marker created *after* the subject policy cannot become effective
before it. The webhook tests use the same idea with two webhooks in one
`ValidatingWebhookConfiguration`, which become active atomically.

## Cost: what is and is not obtainable

The runtime cost is computed on every evaluation (`activation.go` compares it
against the remaining budget) and then discarded. It is **not** in
`ValidateResult`, **not** in the policy status, and **not** in any metric —
`apiserver_validating_admission_policy_check_total` is a counter and
`_check_duration_seconds` is wall-clock latency.

From a real cluster the only observable is the sharp boundary at which the
budget is exhausted, which brackets a cost to roughly ±0.3 % for two admission
round trips (`TestCostBudgetBisect`). Use `oracle.ExactCosts` instead: it reads
the remaining budget straight off `ConditionEvaluator.ForInput` and is exact.

The budget is **not one pot** — see the `Costs` doc comment. Validations and
messageExpressions share one 10,000,000 budget; auditAnnotations get a *fresh*
10,000,000; matchConditions get a separate 2,500,000. A policy is rejected when
any single chain overruns, never when the sum does.
