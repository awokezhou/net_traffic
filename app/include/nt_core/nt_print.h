#ifndef __NT_PRINT_H__
#define __NT_PRINT_H__


#define NT_PRINT_INFO  0x1000
#define NT_PRINT_ERR   0x1001
#define NT_PRINT_WARN  0x1002
#define NT_PRINT_BUG   0x1003
#define NT_PRINT_DBG   0x1004

#define ANSI_GREEN      "\033[92m"
#define ANSI_BLUE       "\033[94m"
#define ANSI_RED        "\033[91m"
#define ANSI_MAGENTA    "\033[95m"
#define ANSI_YELLOW     "\033[93m"
#define ANSI_WHITE      "\033[97m"
#define ANSI_RESET      "\033[0m"

#define nt_debug(...)      nt_print(NT_PRINT_DBG,    __func__, __LINE__, __VA_ARGS__)
#define nt_info(...)       nt_print(NT_PRINT_INFO,   __func__, __LINE__, __VA_ARGS__)
#define nt_err(...)        nt_print(NT_PRINT_ERR,    __func__, __LINE__, __VA_ARGS__)
#define nt_warn(...)       nt_print(NT_PRINT_WARN,   __func__, __LINE__, __VA_ARGS__)
#define nt_bug(...)        nt_print(NT_PRINT_BUG,    __func__, __LINE__, __VA_ARGS__)


#endif /* __NT_PRINT_H__ */

