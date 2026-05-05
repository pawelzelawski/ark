#include <stdio.h>

typedef int (*test_fn_t)(void);

typedef struct {
	const char *name;
	test_fn_t fn;
} test_case_t;

int test_archive_stub(void);
int test_blake3_stub(void);
int test_deflate_stub(void);
int test_edge_stub(void);
int test_extract_stub(void);
int test_fault_stub(void);
int test_integration_stub(void);
int test_sha256_stub(void);
int test_thread_stub(void);

static const test_case_t g_tests[] = {
    {"test_sha256_stub", test_sha256_stub},
    {"test_blake3_stub", test_blake3_stub},
    {"test_deflate_stub", test_deflate_stub},
    {"test_archive_stub", test_archive_stub},
    {"test_thread_stub", test_thread_stub},
    {"test_extract_stub", test_extract_stub},
    {"test_fault_stub", test_fault_stub},
    {"test_edge_stub", test_edge_stub},
    {"test_integration_stub", test_integration_stub},
};

int main(void)
{
	size_t i;

	for (i = 0; i < (sizeof(g_tests) / sizeof(g_tests[0])); i++) {
		(void)g_tests[i].name;
		(void)g_tests[i].fn;
	}
	printf("0/0 tests passed\n");
	return (0);
}
