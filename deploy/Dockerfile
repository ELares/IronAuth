# SPDX-License-Identifier: MIT OR Apache-2.0
#
# THE IMAGE IRONAUTH SHIPS. One file, built by the release lane and by the CI cluster job,
# because they were two heredocs and they had already drifted: the CI copy omitted
# `USER 65532:65532`, so the job that proves the chart runs under `runAsNonRoot` was
# proving it against an image whose default user is root. The chart's securityContext
# would still have forced the uid, which is exactly why the drift was invisible.
#
# `FROM scratch` because the binary is statically linked against musl. There is no shell,
# no package manager and no libc in the image, which is the point: the attack surface is
# the binary, and `docker exec` into it is not a debugging path anyone can take.
#
# Build context expects the binary at ./ironauth.
FROM scratch
COPY ironauth /ironauth
# A non-root uid in the image itself, not only in the pod spec. A deployment that forgets
# `runAsNonRoot` still does not get root, and `docker run` outside Kubernetes matches what
# the chart asks for.
USER 65532:65532
ENTRYPOINT ["/ironauth"]
