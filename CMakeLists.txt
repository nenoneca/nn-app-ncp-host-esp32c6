cmake_minimum_required(VERSION 3.20.0)
# nn-modules location: env (standalone build via nn-app-build) or the
# monorepo sibling (${NN_MODULES_DIR}) fallback so in-tree builds still work.
set(NN_MODULES_DIR "$ENV{NN_MODULES_DIR}")
if(NOT NN_MODULES_DIR)
    set(NN_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../modules)
endif()
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ncp_host_esp32c6)

# nn_proto wire-format library (cross-platform, callback-based crypto).
add_subdirectory(${NN_MODULES_DIR}/libs/nn_proto nn_proto_build)

# fw_common — platform-neutral firmware logic (HDLC, Spinel, …) shared
# with the upcoming Linux gateway daemon (host/gw_linux/).
add_subdirectory(${NN_MODULES_DIR}/libs/fw_common fw_common_build)

target_sources(app PRIVATE
    src/main.c
    # hdlc.c + spinel.c moved to modules/libs/fw_common; pulled in via
    # add_subdirectory() above when CONFIG_FW_COMMON=y.
    src/ncp_link.c
    src/ncp_netif.c
    src/nat64.c
    src/border_agent.c
    src/ra_sender.c
    # gw_identity core moved to modules/libs/fw_common/src/gw_identity.c;
    # only the Zephyr shell wrapper stays in the app.
    src/gw_identity_shell.c
    src/proto_tcp.c
    src/proto_udp.c
    src/proto_router.c
    src/gw_commands.c
    # gw_provision + gw_ble_provision moved to modules/libs/fw_common/.
    # Only the Zephyr shell wrapper stays here.
    src/gw_provision_shell.c
    src/gw_ot_apply.c
    src/gw_thread_state.c
    # M6 unified: gateway uses the same hub_crypto X25519 ECIES path
    # as sensors.  hub_crypto.c moved to modules/libs/fw_common/ and is
    # pulled in via the fw_common add_subdirectory() above
    # (CONFIG_FW_COMMON=y in prj.conf).  No direct source reference
    # needed here anymore.
    src/gw_fw_http.c
    src/gw_ota.c
    src/gw_peer_reset.c
    src/ncp_ota_client.c
    src/gw_watchdog.c
)

target_include_directories(app PRIVATE
    src
    ${NN_MODULES_DIR}/libs/node_mgr/include
    ${NN_MODULES_DIR}/libs/fw_common/include
)
