# Fixtures

These files are copied unmodified from the TypeScript repository
(`sdk/packages/core/tests/fixtures`). They are real vendor data, not data made for this project.
`vectors.json` is generated from them by `gen-vectors.mts` running the TypeScript verifiers.

| File | Source | License |
| --- | --- | --- |
| `android-key-attestation.json` | Chains produced by TestDPC on Android devices, from `google/android-key-attestation`, `src/test/resources/der` at commit f9846cd019289f1788cec65b062d9f81c0c4884c (https://github.com/google/android-key-attestation) | Apache License 2.0 |
| `apple-app-attest.json`, entry `apple_guide_sample` | Sample data of Apple's Attestation Object Validation Guide, fetched 2026-10-18 from developer.apple.com (example app com.example.myapp) | Apple documentation sample |
| `apple-app-attest.json`, entry `veehaitch_ios_14_4` | `veehaitch/devicecheck-appattest`, `src/test/resources/ios-14.4.yaml`, a real device recorded 2021-01-23 (https://github.com/veehaitch/devicecheck-appattest) | Apache License 2.0 |
| `apple-app-attest.json`, entry `termakan_ios_27_0_1` | `jewei/app-attest-php`, `spec/termakan-ios27-attestation.json`, a real iPhone recorded 2026-10-12 (https://github.com/jewei/app-attest-php) | MIT License |
| `tpm2-quote-gce.json` | vTPM quotes of a Google Compute Engine Shielded VM from `google/go-tpm-tools`, `internal/test/attestations/gce-cos-85-nonce9009.pb` and `gce-cos-85-no-nonce.pb` at commit 7350267efdfa67fc62be505004fd61d7d05e5288, decoded from protobuf (https://github.com/google/go-tpm-tools), plus Google's published EK intermediate and root (https://pki.goog/cloud_integrity/) fetched 2026-10-18 | Apache License 2.0 |

The Apache License 2.0 text is at https://www.apache.org/licenses/LICENSE-2.0 and the MIT
License text is at https://opensource.org/license/mit. The fixtures are test inputs only and are
not linked into any build of the library.

To regenerate `vectors.json` after a TypeScript change, run from the Go repository root with the
TypeScript repository next to it:

    THEAUTH_CORE=../sdk/packages/core ../sdk/packages/core/node_modules/.bin/tsx iot/attest/testdata/gen-vectors.mts iot/attest/testdata/vectors.json
