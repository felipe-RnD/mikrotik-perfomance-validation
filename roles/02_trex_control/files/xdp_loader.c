/*
 * XDP Loader
 *
 * This program attaches the eBPF program from "l3_reflector.bpf.o"
 * to a specified network interface.
 *
 * Compile: (See Makefile)
 * Run: sudo ./xdp_loader -i <interface_name>
 *
 * It will remain running. Press Ctrl+C to detach the XDP program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>

static int ifindex = 0;
static volatile int stop_program = 0;

static void int_handler(int sig)
{
    stop_program = 1;
}

static void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s -i <interface>\n", prog_name);
    fprintf(stderr, "  -i, --interface <ifname>   Network interface to attach XDP program\n");
    fprintf(stderr, "  -h, --help                 Show this help message\n");
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    char *iface = NULL;
    int opt;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "hi:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            iface = strdup(optarg);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!iface) {
        fprintf(stderr, "Error: Interface must be specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Error: Interface '%s' not found: %s\n", iface, strerror(errno));
        free(iface);
        return 1;
    }

    // Set up Ctrl+C handler
    signal(SIGINT, int_handler);
    signal(SIGTERM, int_handler);

    // Open and load the eBPF object file
    obj = bpf_object__open_file("l3_reflector.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error: Failed to open BPF object file: %s\n", strerror(errno));
        free(iface);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error: Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        free(iface);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_reflector_prog");
    if (!prog) {
        fprintf(stderr, "Error: Failed to find 'xdp_reflector_prog' in BPF object\n");
        bpf_object__close(obj);
        free(iface);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    // Attach the XDP program
    // We use bpf_set_link_xdp_fd() which is the modern libbpf function.
    // The old bpf_xdp_attach() is deprecated.
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Error: Failed to attach XDP program to interface '%s': %s\n",
                iface, strerror(errno));
        bpf_object__close(obj);
        free(iface);
        return 1;
    }

    printf("XDP reflector successfully attached to %s.\n", iface);
    printf("Reflecting UDP ports 12-16. All other traffic is passed to kernel.\n");
    printf("Press Ctrl+C to detach and exit.\n");

    // Wait for Ctrl+C
    while (!stop_program) {
        sleep(1);
    }

    // Detach and clean up
    printf("\nDetaching XDP program from %s...\n", iface);
    // Detach by passing -1 as the program file descriptor
    if (bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Error: Failed to detach XDP program: %s\n", strerror(errno));
    } else {
        printf("Detached successfully.\n");
    }

    bpf_object__close(obj);
    free(iface);
    return 0;
}
