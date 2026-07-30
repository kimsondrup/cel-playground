# CEL Playground
![GitHub](https://img.shields.io/github/license/undistro/cel-playground)
[![Go Report Card](https://goreportcard.com/badge/github.com/undistro/cel-playground)](https://goreportcard.com/report/github.com/undistro/cel-playground)
[![slack](https://img.shields.io/badge/Slack-Join-4a154b?logo=slack)](https://join.slack.com/t/undistrocommunity/shared_invite/zt-21slyrao4-dTW_XtOB90QVj05txOX6rA)

CEL Playground is an interactive WebAssembly (Wasm) powered environment to explore and experiment with the [Common Expression Language (CEL)](https://github.com/google/cel-spec).
It provides a simple and user-friendly interface to write and quickly evaluate CEL expressions.

## Modes

The playground evaluates several kinds of CEL input, selectable from the **Modes** button:

- **CEL Expression** — a bare expression against an arbitrary input document.
- **Validating Admission Policy** — a
  [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
  for seeing whether a request would be *allowed*: `matchConditions`,
  `variables`, `validations` and `auditAnnotations`.
- **Mutating Admission Policy** — a
  [MutatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/)
  (`admissionregistration.k8s.io/v1`; `v1beta1` and `v1alpha1` documents are
  accepted too), for seeing how a request's object is *rewritten*:
  `matchConditions`, `variables`, the object produced by each `spec.mutations`
  entry for both the `ApplyConfiguration` and `JSONPatch` patch types, and a diff
  against the object you started from.
- **Web Hooks** — `matchConditions` on validating and mutating webhook
  configurations.

### What the Kubernetes modes do not simulate

The playground evaluates expressions; it is not an apiserver. For the Mutating
Admission Policy mode in particular:

- `matchConstraints` are parsed but not evaluated. The mutations run against
  whatever is in the Object tab, whether or not the `resourceRules` would select
  it, so only `matchConditions` can stop one from running.
- `params` / `paramKind` have no input, so an expression reading `params` errors
  and `has(params...)` is false.
- Authorizer checks ignore `fieldSelector()` and `labelSelector()`: the Authorizer
  tab has no way to express a selector. In `matchConditions` and `variables` those
  functions do not exist at all and the expression fails with `no such overload`;
  inside a mutation they do exist, and the check is answered from the un-narrowed
  entry, which is warned about in the result panel.
- `reinvocationPolicy` changes nothing: each mutation runs exactly once.
- `failurePolicy` changes nothing: there is no request to reject, so a failed
  mutation is reported and the rest still run, where a cluster with the default
  `Fail` would deny the whole request.
- The object is used exactly as typed. A cluster applies API defaults before
  admission runs and again after every mutation, so a `!has(...)` guard can look
  like it fires here when it would not.
- Merge semantics come from the schemas compiled into this binary, which cover
  the built-in APIs only. Custom resources fall back to treating lists as atomic,
  which is warned about in the result panel.

Each run puts the limits on screen rather than leaving them only here. The ones
that are properties of the policy document -- `matchConstraints`, `paramKind`,
`reinvocationPolicy`, `failurePolicy` and defaulting -- are repeated in a
`notSimulated` section. The ones that depend on the input, such as a narrowed
authorizer check or a custom resource falling back to atomic lists, are reported
as warnings alongside the result they affected.

## CEL libraries

CEL Playground is built by compiling Go code to WebAssembly and includes the following libraries that are available in the environment:

- CEL [extended string function library](https://pkg.go.dev/github.com/google/cel-go/ext#Strings)
- [Kubernetes list library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-list-library)
- [Kubernetes regex library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-regex-library)
- [Kubernetes URL library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-url-library)
- [Kubernetes semver library](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-semver-library)

The Kubernetes policy modes (Validating Admission Policy, Mutating Admission Policy and Web Hooks)
additionally include the [IP](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-ip-library),
[CIDR](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-cidr-library)
and [format](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-format-library)
libraries, two-variable comprehensions, and the CEL list extension (`.sort()`),
matching the CEL environment a Kubernetes apiserver exposes.

Take a look at the environment options in [eval/eval.go](eval/eval.go) (the CEL
mode) and [k8s/cel.go](k8s/cel.go) (the Kubernetes modes).

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
