#ifndef PE_SPAWN_BOOTSTRAP_H
#define PE_SPAWN_BOOTSTRAP_H

#include <mach/mach.h>
#include <spawn.h>
#include <stdbool.h>

/* A successful copy owns one send right, unless the override explicitly clears the port. */
int pe_spawn_bootstrap_copy(const posix_spawnattr_t *attributes, bool *present, mach_port_t *port);
int pe_spawn_bootstrap_initialize(void);

#endif
