# CEL Playground
![GitHub](https://img.shields.io/github/license/undistro/cel-playground)
[![Go Report Card](https://goreportcard.com/badge/github.com/undistro/cel-playground)](https://goreportcard.com/report/github.com/undistro/cel-playground)
[![slack](https://img.shields.io/badge/Slack-Join-4a154b?logo=slack)](https://join.slack.com/t/undistrocommunity/shared_invite/zt-21slyrao4-dTW_XtOB90QVj05txOX6rA)

CEL Playground is an interactive WebAssembly (Wasm) powered environment to explore and experiment with the [Common Expression Language (CEL)](https://github.com/google/cel-spec).
It provides a simple and user-friendly interface to write and quickly evaluate CEL expressions.

## CEL libraries

CEL Playground is built by compiling Go code to WebAssembly and includes the following libraries that are available in the environment:

- CEL [extended string function library](https://pkg.go.dev/github.com/google/cel-go/ext#Strings)
- [Kubernetes list library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-list-library)
- [Kubernetes regex library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-regex-library)
- [Kubernetes URL library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-url-library)
- [Kubernetes semver library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-semver-library)

The Kubernetes policy modes (Validating Admission Policy and Web Hooks) do not
assemble an environment of their own. They compile and evaluate expressions with
the apiserver's own compiler, `k8s.io/apiserver/pkg/admission/plugin/cel`, so
whichever libraries a cluster offers are exactly the ones offered here -- the
[IP](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-ip-library),
[CIDR](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-cidr-library)
and [format](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-format-library)
libraries, two-variable comprehensions and the CEL list extension (`.sort()`)
among them. The footer reports which Kubernetes release's CEL environment is in
use; an apiserver stays compatible with the release before its own, so that is
one minor behind the apiserver the playground is built from.

Take a look at the environment options in [eval/eval.go](eval/eval.go) for the
CEL mode.

## What the expressions can see

| | |
|---|---|
| `object` | the object from the request; null for DELETE |
| `oldObject` | the existing object; null for CREATE |
| `request` | the AdmissionRequest tab, read strictly |
| `namespaceObject` | the Namespace tab, trimmed the way a cluster trims it. Null while matchConditions are evaluated, because the matcher passes no namespace |
| `variables` | `spec.variables`, lazily. Not available in matchConditions: the apiserver refuses to store a policy whose matchConditions name it |
| `authorizer`, `authorizer.requestResource` | the RBAC tab. Not declared for a `messageExpression`, and declared but unbound for an `auditAnnotation`, both as on a cluster |
| `params` | declared only when the policy declares `spec.paramKind`. There is no params tab, so it is **null** — an expression that reads a field of it fails, as it would on a cluster whose paramRef selected nothing |

## Reading the result panel

An apiserver evaluates a `ValidatingAdmissionPolicy` in four batches --
`matchConditions`, `validations`, `messageExpressions`, `auditAnnotations` --
and the panel has a section per batch, plus a section for the `spec.variables`
each batch read.

That is why the same variable can appear more than once, with the same value and
the same cost. Each batch builds its own copy of `variables`, so a variable read
from both a validation and an audit annotation is evaluated twice and charged
twice. The total at the top is the sum of everything that ran.

The total is not a budget, though, and a policy is never rejected for exceeding
it. There are three separate budgets: `matchConditions` get 2,500,000 each,
`validations` and `messageExpressions` share 10,000,000, and `auditAnnotations`
start again from a full 10,000,000. When a run goes past one of them an
**exceededBudgets** section appears at the top of the panel saying which. A real
cluster would abandon the rest of that chain and reject the request; the
playground keeps going so the expression that overran is still visible.

## The RBAC tab

Policies and webhook match conditions can ask whether the user making the
request is allowed to do something:

```
authorizer.group("apps").resource("deployments").namespace("default").check("escalate").allowed()
```

The RBAC tab is the answer to those questions. It takes real
`rbac.authorization.k8s.io/v1` `Role`, `ClusterRole`, `RoleBinding` and
`ClusterRoleBinding` objects, `---` separated, and resolves them with the RBAC
authorizer Kubernetes itself runs -- so wildcards, `resourceNames`, subresource
paths, aggregated ClusterRoles, `nonResourceURLs` prefixes and the
`system:serviceaccounts` groups behave the way they do on a cluster. The subject
is whatever `request.userInfo` says, or the service account named by
`authorizer.serviceAccount(namespace, name)`.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-escalator
  namespace: default
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-deployment-escalator
  namespace: default
subjects:
  - kind: User
    apiGroup: rbac.authorization.k8s.io
    name: alice
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deployment-escalator
```

Two things follow from this being real RBAC. A verb does not have to be one the
API serves -- `escalate` above is a question only the policy cares about, and a
rule may name any verb. And RBAC has no way to say no, only to stay silent, so
`denied()` is always false and an unauthorized check reports `allowed()` false
with no opinion, exactly as it would on a cluster running RBAC alone.

The tab is read strictly: an unknown field, a duplicate key, an unexpected kind
or an apiVersion other than `rbac.authorization.k8s.io/v1` is reported rather
than ignored.

## Development

Build the Wasm binary:
```shell
make build
```

Serve the static files:
```shell
make serve
```

## Community

To engage with our community, you can use the following resources:
- Give us a [star :star:](https://github.com/undistro/cel-playground/stargazers) - If you want us to continue developing and improving CEL Playground
- [Contributing to CEL Playground](https://github.com/undistro/cel-playground/blob/main/CONTRIBUTING.md) - Start here if you're interested in contributing to the project
- [Code of Conduct](https://github.com/undistro/cel-playground/blob/main/CODE_OF_CONDUCT.md) - Learn about the guidelines that govern our community interactions
- [Slack Channel](https://join.slack.com/t/undistrocommunity/shared_invite/zt-21slyrao4-dTW_XtOB90QVj05txOX6rA) - Join us on Slack to get support or discuss the project
- [Community Sessions](https://tinyurl.com/undistro-community-calendar) - Join our monthly community meetings and bi-weekly office hours ([agenda and meeting notes](https://docs.google.com/document/d/13AhGiyIiX58UJMw7CDJi_T8e1_SC7f7p1kE2PcyDwRU/edit#heading=h.7k7sl4hlyyqw))
- [Roadmap](https://github.com/undistro/cel-playground/blob/main/roadmap.md) - Discover what's next for the project
- [Adopters](https://github.com/undistro/cel-playground/blob/main/ADOPTERS.md) - Is your company using CEL Playground? Let us know, and we'll feature you here!

## License

CEL Playground is available under the Apache 2.0 license. See the [LICENSE](LICENSE) file for more info.
