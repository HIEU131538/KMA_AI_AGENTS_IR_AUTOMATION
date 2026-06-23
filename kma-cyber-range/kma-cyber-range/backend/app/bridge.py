def normalize_log(
    message,
    source_ip,
    event_type,
    timestamp
):

    return {
        "message":
            message,

        "source_ip":
            source_ip,

        "event_type":
            event_type,

        "timestamp":
            timestamp
    }
