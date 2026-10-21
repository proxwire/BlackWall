#include <stddef.h>

#if defined(_WIN32)
#define FIXTURE_EXPORT __declspec(dllexport)
#else
#define FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

/*
 * An inert analysis fixture.  It performs no I/O, networking, persistence, or
 * process creation.  The exported strings give static tools stable evidence.
 */
FIXTURE_EXPORT const char *blackwall_fixture_marker(void) {
    return "BLACKWALL_INERT_NATIVE_FIXTURE";
}

FIXTURE_EXPORT const char *blackwall_fixture_url(void) {
    return "https://native.fixture.invalid/api";
}

FIXTURE_EXPORT const char *blackwall_fixture_config(void) {
    return "campaign=native-inert";
}

int main(void) {
    const char *marker = blackwall_fixture_marker();
    return marker == NULL;
}
