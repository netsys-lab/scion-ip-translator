#include <chrono>
#include <errno.h>
#include <exception>
#include <getopt.h>
#include <iostream>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <thread>

#include "libbpf.h"
#include "libbpf_common.h"

#include "EgressLoader.hxx"
#include "IngressLoader.hxx"
#include "PathService.hxx"

using namespace std::chrono_literals;

static volatile sig_atomic_t exiting = 0;

static void sig_int(int)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void usage(char *name)
{
	std::cout << "usage: " << name << " [-i interface] [-e interface] [-d sciond]\n"
		  << "\n"
		  << "options:\n"
		  << "  -i interface          Specify ingress interface to attach to\n"
		  << "  --ingress=interface   Alias for -i\n"
		  << "  -e interface          Specify egress interface to attach to\n"
		  << "  --egress=interface    Alias for -e\n"
		  << "  -d sciond             Address of SCION daemon (IP:port)\n"
		  << "  --sciond=sciond       Alias for -d\n";
	std::exit(EXIT_SUCCESS);
}

// clang-format off
static struct option longopts[] = {
  { "ingress", required_argument, NULL, 'i' },
  { "egress", required_argument, NULL, 'e' },
  { "sciond", required_argument, NULL, 'd' },
  { NULL, 0, NULL, 0 } };
// clang-format on

int main(int argc, char **argv)
{
	int ch;
	std::string in_if, eg_if, sciond;
	struct bpf_map *pathMap;

	libbpf_set_print(libbpf_print_fn);

	// Parse commandline arguments
	if (argc < 2)
		usage(argv[0]);
	while ((ch = getopt_long(argc, argv, "d:e:i:", longopts, NULL)) != -1) {
		switch (ch) {
		case 'i':
			in_if = optarg;
			break;
		case 'e':
			eg_if = optarg;
			break;
		case 'd':
			sciond = optarg;
			break;
		// Print usage
		default:
			usage(argv[0]);
		}
	}

  // Make sure all required arguments are present
	if ((eg_if.empty()  && in_if.empty()) || (!eg_if.empty() && sciond.empty())) {
		std::cerr << "Missing argument\n";
		return EXIT_FAILURE;
	}

	// Register signal handler for graceful shutdown
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		std::cerr << "Can't set signal handler: " << strerror(errno) << "\n";
		return EXIT_FAILURE;
	}

  // Attach XDP program to ingress interface
	IngressLoader inLoader{};
  if(!in_if.empty()) {
    try {
      inLoader.attach(in_if);
      std::cerr << "Successfully attached to ingress interface " << in_if << '\n';
    } catch (const std::exception &e) {
      std::cerr << "Could not attach ingress translator to interface " << in_if << '\n';
      return EXIT_FAILURE;
    }
  }

  // Attach TC program to egress interface
	EgressLoader egLoader{};
  if(!eg_if.empty()) {
    try {
      egLoader.attach(eg_if);
      std::cerr << "Successfully attached to egress interface " << eg_if << '\n';
    } catch (const std::exception &e) {
      std::cerr << "Could not attach egress translator to interface " << eg_if << '\n';
      return EXIT_FAILURE;
    }
  } else {
    // Kinda bad practice here, but PathService is unfortunately implemented
    // in a way that makes this easier. Problem for future-me :^)
    goto start_loop;
  }

  // Obtain handle for the Path Cache BPF map
	try {
		pathMap = egLoader.pathMap();
	} catch (std::exception &e) {
		std::cerr << "Could not obtain path map handle\n";
		return EXIT_FAILURE;
	}

	PathService pathService(pathMap, egLoader.requestQueue());

  // Initialize Path Service, connecting to the SCION daemon
	try {
		pathService.init(sciond);
	} catch (std::exception &e) {
		std::cerr << "Could not connect to SCION Daemon\n";
		return EXIT_FAILURE;
	}

  // Run Path Service in separate thread
	std::jthread pathServiceThread([&pathService]() {
    std::cerr << "Starting Path Service\n";
    try {
      pathService.run();
    } catch (std::exception &e) {
      std::cerr << "An error in the Path Service has occured\n";
      exiting = 1;
    }
  });

start_loop:
	std::cout << "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
		     "to see output of the BPF program.\n";

	// Keep program running
	while (!exiting) {
		std::cerr << ".";
    std::this_thread::sleep_for(1s);
	}

	return EXIT_SUCCESS;
}
