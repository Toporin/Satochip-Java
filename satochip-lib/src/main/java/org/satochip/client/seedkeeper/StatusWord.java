package org.satochip.client.seedkeeper;

public enum StatusWord {
    OK(0x9000, "Ok"),
    LOCK_ERROR(0x9C30, "Lock error"),
    EXPORT_NOT_ALLOWED(0x9C31, "Export not allowed"),
    USAGE_NOT_ALLOWED(0x9C36, "Usage not allowed"),
    WRONG_SECRET_TYPE(0x9C38, "Wrong secret type"),
    UNKNOWN_ERROR(-1, "Unknown error"); // Default case for unknown errors

    private final int value;
    private final String message;

    StatusWord(int value, String message) {
        this.value = value;
        this.message = message;
    }

    public int getValue() {
        return value;
    }

    public String getMessage() {
        return message;
    }

    public static StatusWord fromValue(int value) {
        for (StatusWord statusWord : StatusWord.values()) {
            if (statusWord.value == value) {
                return statusWord;
            }
        }
        return UNKNOWN_ERROR;
    }
}

