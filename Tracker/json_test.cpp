#include <stdio.h>
#include <cstring>
#include "json.h"

int main() {
    auto obj = json::jobject::parse("{}");
    printf("%p\n", &obj);
    return 0;
}