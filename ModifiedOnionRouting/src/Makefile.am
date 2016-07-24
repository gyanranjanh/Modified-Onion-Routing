SUBDIRS   = sha2_third_party
AM_CFLAGS = -I./sha2_third_party -DENABLE_OR_LOG

bin_PROGRAMS = m_onion_routing
m_onion_routing_SOURCES = or_main.c or_log.c or_util.c or_test.c or_security_module.c or_time.c or_common.c
m_onion_routing_SOURCES += or_sender.c or_receiver.c or_router.c or_mem_util.c or_os_helper.c
m_onion_routing_SOURCES += or_exit_funnel.c or_application_proxy.c or_onion_proxy.c
m_onion_routing_LDADD = -lpthread -lm -ldl ./sha2_third_party/libsha.a

