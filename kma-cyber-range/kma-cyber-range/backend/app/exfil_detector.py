def detect_data_exfiltration(events):

    employee_reads = 0

    for event in events:

        if (
            event.get("event")
            ==
            "employee_view"
        ):
            employee_reads += 1

    return employee_reads >= 20
