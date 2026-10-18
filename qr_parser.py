from urllib.parse import urlparse, parse_qs


def parse_upi_qr(qr_text):

    result = {
        "upi_id": "",
        "merchant_name": "",
        "amount": None,
        "raw_qr": qr_text
    }

    if not qr_text:
        return result

    qr_text = qr_text.strip()

    try:

        parsed = urlparse(qr_text)

        query = parse_qs(
            parsed.query
        )

        if "pa" in query:
            result["upi_id"] = query["pa"][0]

        if "pn" in query:
            result["merchant_name"] = query["pn"][0]

        if "am" in query:

            try:
                result["amount"] = float(
                    query["am"][0]
                )

            except ValueError:
                result["amount"] = None

    except Exception as e:

        print(
            "QR parsing error:",
            e
        )

    return result