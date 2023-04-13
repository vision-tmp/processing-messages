#ifndef PROCESS_MESSAGES_H
#define PROCESS_MESSAGES_H

//#define DEBUG_LOG // uncomment it to switch on debug logging or add -DDEBUG_LOG to gcc

#define IN_FILE_NAME "data_in.txt"
#define OUT_FILE_NAME "data_out.txt"

#define MESSAGE_IN_ORIGINAL_BYTES 258
#define CRC32_IN_ORIGINAL_BYTES 4
#define TYPE_IN_ORIGINAL_BYTES 1
#define LENGTH_IN_ORIGINAL_BYTES 1

#define MASK_IN_ORIGINAL_BYTES 4

#define DATA_MAX_SIZE_IN_ORIGINAL_BYTES \
(MESSAGE_IN_ORIGINAL_BYTES - TYPE_IN_ORIGINAL_BYTES - \
LENGTH_IN_ORIGINAL_BYTES - CRC32_IN_ORIGINAL_BYTES)

#define DATA_MAX_SIZE_IN_TETRADS (DATA_MAX_SIZE_IN_ORIGINAL_BYTES / 4 + \
((DATA_MAX_SIZE_IN_ORIGINAL_BYTES % 4) ? 1 : 0))

#define MESSAGE_IN_HEX_CHARS (MESSAGE_IN_ORIGINAL_BYTES * 2)
#define CRC32_IN_HEX_CHARS (CRC32_IN_ORIGINAL_BYTES * 2)
#define TYPE_IN_HEX_CHARS (TYPE_IN_ORIGINAL_BYTES * 2)
#define LENGTH_IN_HEX_CHARS (LENGTH_IN_ORIGINAL_BYTES * 2)

#define MASK_IN_HEX_CHARS (MASK_IN_ORIGINAL_BYTES * 2)

#define DATA_MAX_SIZE_IN_HEX_CHARS (DATA_MAX_SIZE_IN_ORIGINAL_BYTES * 2)

#define NUMBER_OF_HEX_IN_BYTE 2
#define NUMBER_OF_BYTES_IN_TETRADS 4
#define NUMBER_OF_HEX_IN_TETRADS (NUMBER_OF_BYTES_IN_TETRADS * 2)

#define NO_ERROR 0
#define ERROR_FILE_READ -1
#define ERROR_FILE_WRITE -2
#define ERROR_MESSAGE_LENGTH -3
#define ERROR_WRONG_DIGIT -4
#define ERROR_WRONG_LENGTH_IN_MESSAGE -5
#define ERROR_MASK_WITHOUT_MESSAGE -6
#define ERROR_MESSAGE_WITHOUT_MASK -7
#define ERROR_THERE_IS_NO_MESSAGE_OR_MASK -8
#define ERROR_CRC32 -9
#define ERROR_INIT_FILE_READING -10
#define ERROR_MEMORY_ALLOCATION -11
#define ERROR_HEXSTRING_FORMAT -12
#define ERROR_NUMBER_TO_TETRADSTR -13
#define ERROR_NUMBER_TO_BYTESTR -14

#define SIZE_OF_ARRAY(a) sizeof(a) / sizeof(*a)

#define ASSERT(x) do{ if(!(x)) { fprintf(stderr, "%s:%d:%s(*) Assertion failed ("#x")", \
__FILE__, __LINE__, __func__); abort(); } } while(0)

#ifdef DEBUG_LOG
#define DEBUG_PRINTF(format, x) do{ printf("%s:%d:%s(*) %s:"format"\n", \
__FILE__, __LINE__, __func__, #x, x); } while(0)
#define DEBUG_STRING(x) do{ printf("%s:%d:%s(*) %s (string in quotes):\"%s\"\n", \
__FILE__, __LINE__, __func__, #x, x); } while(0)
#define DEBUG_INT_D(x) do{ printf("%s:%d:%s(*) %s:%d\n", \
__FILE__, __LINE__, __func__, #x, x); } while(0)
#define DEBUG_MSG(x) do{ printf("%s:%d:%s(*) %s\n", \
__FILE__, __LINE__, __func__, x); } while(0)
#define DEBUG_PRINT_TETRAD(x) do{ printf("%s:%d:%s(*) %s:%c%c%c%c%c%c%c%c\n", \
__FILE__, __LINE__, __func__, #x, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]); } while(0)
#else
#define DEBUG_PRINTF(format, x)
#define DEBUG_STRING(x)
#define DEBUG_INT_D(x)
#define DEBUG_MSG(x)
#define DEBUG_PRINT_TETRAD(x)
#endif

typedef struct {
    const char *message_hexstr;
    unsigned char length_in_bytes;
    char type_hexstring[TYPE_IN_HEX_CHARS + 1];
    char length_hexstring[LENGTH_IN_HEX_CHARS + 1];
    char data_hexstring[DATA_MAX_SIZE_IN_HEX_CHARS + 1];
    char crc32_hexstring[CRC32_IN_HEX_CHARS + 1];
    const char *data_hexstring_ptr;
    unsigned long data_as_numbers_in_tetrads[DATA_MAX_SIZE_IN_TETRADS];
    unsigned long crc32;
    unsigned char number_of_tetrads_in_data;
    char data_hexstring_modified[DATA_MAX_SIZE_IN_HEX_CHARS + 1];
    unsigned long crc32_modified;
} message_t;

typedef struct {
    int formatted_output;
} options_t;

unsigned long crc32custom(const char *string_of_hexchars, int number_of_bytes);
int hextetrad_to_number(const char *hextetrad, unsigned long *number_p);
int hexbyte_to_number(const char *hexbyte, unsigned long *number_p);
int number_to_hextetrad(unsigned long number, char *hextetrad);
int number_to_hexbyte(unsigned long number, char *hexbyte);
char* get_error_message(int error_code);
int get_message_struct(const char *message_hexstr, message_t *message);
int process_pair(const char *message, const char *mask, message_t *result);
int process_all_messages(const char *in_file_name, const char *out_file_name,
                         const options_t *options);

#endif // PROCESS_MESSAGES_H
