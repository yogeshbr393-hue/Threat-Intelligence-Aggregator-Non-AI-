from validator import is_valid_ioc


def normalize_iocs(raw_data, source_name):

    normalized = []

    for item in raw_data:

        try:

            value = item.get("value", "").strip()

            if not is_valid_ioc(value):
                continue

            normalized.append({
                "type": item.get("type", "ioc"),
                "value": value,
                "source": source_name
            })

        except:
            pass

    return normalized
