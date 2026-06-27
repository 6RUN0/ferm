# Image for the docker-coexistence e2e: docker-in-docker (a real docker
# 29 engine with the native nftables firewall backend) plus a slim
# Python and the nft tool.  The ferm sources and the driver are
# bind-mounted at run time, so the image never goes stale.
#
# Unlike the nft_e2e image -- which hand-plants a foreign table to *stand
# in* for docker -- this one runs the genuine docker engine, so the
# coexistence invariant is proven against real ``docker-bridges`` tables.
#
# The base already ships dockerd + the dind entrypoint; nftables is the
# firewall tool the inner dockerd shells out to (the stock dind image
# omits it, and dockerd refuses to start with --firewall-backend=nftables
# when ``nft`` is absent), and python3 runs ferm and the driver.
FROM docker:29-dind

# hadolint ignore=DL3018
RUN apk add --no-cache nftables python3
WORKDIR /work
