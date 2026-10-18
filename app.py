from flask import Flask, request, jsonify
from flask_cors import CORS

import joblib
import pandas as pd

import urllib.parse
import re
import os
import json
import hashlib
from datetime import datetime


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
# FILE PATHS
# ============================================================

MODEL_PATH = os.path.join(
    "models",
    "qr_model.joblib"
)

FEATURES_PATH = os.path.join(
    "models",
    "feature_columns.joblib"
)

HISTORY_PATH = "upi_history.json"


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(MODEL_PATH)

FEATURES = joblib.load(
    FEATURES_PATH
)

print("\n========================================")
print("UPI GUARD MODEL LOADED")
print("========================================")
print("Model features:", FEATURES)
print("Amount used for fraud calculation: NO")
print("========================================\n")


# ============================================================
# TRUSTED UPI HANDLES
# ============================================================

TRUSTED_HANDLES = {
    "okaxis",
    "okicici",
    "oksbi",
    "okhdfcbank",
    "ybl",
    "ibl",
    "axl",
    "paytm",
    "ptys"
}


# ============================================================
# SUSPICIOUS WORDS
# ============================================================

SUSPICIOUS_TERMS = {
    "support",
    "verify",
    "verification",
    "refund",
    "reward",
    "winner",
    "cash",
    "bonus",
    "offer",
    "claim",
    "secure",
    "kyc",
    "update",
    "urgent",
    "help",
    "prize"
}


# ============================================================
# LOAD HISTORY
# ============================================================

def load_history():

    if not os.path.exists(HISTORY_PATH):
        return {}

    try:

        with open(
            HISTORY_PATH,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as e:

        print(
            "History load error:",
            e
        )

        return {}


# ============================================================
# SAVE HISTORY
# ============================================================

def save_history(history):

    try:

        with open(
            HISTORY_PATH,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                history,
                file,
                indent=4
            )

    except Exception as e:

        print(
            "History save error:",
            e
        )


# ============================================================
# PARSE UPI QR
# ============================================================

def parse_upi_qr(qr_text):

    result = {
        "upi_id": None,
        "merchant_name": None,
        "amount": None
    }

    if not qr_text:
        return result

    qr_text = qr_text.strip()

    try:

        # ----------------------------------------------------
        # Standard UPI URI
        # ----------------------------------------------------

        if qr_text.lower().startswith("upi://"):

            parsed = urllib.parse.urlparse(
                qr_text
            )

            params = urllib.parse.parse_qs(
                parsed.query
            )

            if "pa" in params:

                result["upi_id"] = (
                    params["pa"][0]
                )

            if "pn" in params:

                result["merchant_name"] = (
                    params["pn"][0]
                )

            # Amount is extracted ONLY so Android
            # can display it.
            #
            # It is NOT used for fraud calculation.

            if "am" in params:

                try:

                    result["amount"] = float(
                        params["am"][0]
                    )

                except ValueError:

                    result["amount"] = None

        else:

            # ------------------------------------------------
            # Fallback QR parsing
            # ------------------------------------------------

            pa_match = re.search(
                r"(?:pa=)([^&]+)",
                qr_text,
                re.IGNORECASE
            )

            pn_match = re.search(
                r"(?:pn=)([^&]+)",
                qr_text,
                re.IGNORECASE
            )

            am_match = re.search(
                r"(?:am=)([^&]+)",
                qr_text,
                re.IGNORECASE
            )

            if pa_match:

                result["upi_id"] = (
                    urllib.parse.unquote(
                        pa_match.group(1)
                    )
                )

            if pn_match:

                result["merchant_name"] = (
                    urllib.parse.unquote(
                        pn_match.group(1)
                    )
                )

            if am_match:

                try:

                    result["amount"] = float(
                        am_match.group(1)
                    )

                except ValueError:

                    result["amount"] = None

    except Exception as e:

        print(
            "QR parsing error:",
            e
        )

    return result


# ============================================================
# NORMALIZE UPI ID
# ============================================================

def normalize_upi_id(upi_id):

    if not upi_id:
        return ""

    return upi_id.strip().lower()


# ============================================================
# GET UPI HANDLE
# ============================================================

def get_handle(upi_id):

    upi_id = normalize_upi_id(
        upi_id
    )

    if "@" not in upi_id:
        return ""

    return upi_id.split(
        "@",
        1
    )[1].strip()


# ============================================================
# GET UPI USERNAME / PREFIX
# ============================================================

def get_upi_prefix(upi_id):

    upi_id = normalize_upi_id(
        upi_id
    )

    if "@" not in upi_id:
        return upi_id

    return upi_id.split(
        "@",
        1
    )[0].strip()


# ============================================================
# QR CHARACTERISTICS
# ============================================================

def calculate_qr_characteristics(
    upi_id,
    merchant_name
):

    upi_id = normalize_upi_id(
        upi_id
    )

    handle = get_handle(
        upi_id
    )

    prefix = get_upi_prefix(
        upi_id
    )

    merchant = (
        merchant_name or ""
    ).strip().lower()


    # --------------------------------------------------------
    # No UPI ID
    # --------------------------------------------------------

    if not upi_id:

        return {
            "qr_risk": 0.80,
            "reason": "UPI ID could not be extracted"
        }


    risk = 0.0

    reasons = []


    # ========================================================
    # HANDLE ANALYSIS
    # ========================================================

    if handle in TRUSTED_HANDLES:

        risk += 0.03

    else:

        risk += 0.18

        reasons.append(
            "unknown UPI handle"
        )


    # ========================================================
    # SUSPICIOUS WORD ANALYSIS
    # ========================================================

    suspicious_found = []

    full_text = (
        upi_id + " " + merchant
    ).lower()

    for term in SUSPICIOUS_TERMS:

        if term in full_text:

            suspicious_found.append(
                term
            )


    if suspicious_found:

        risk += 0.35

        reasons.append(
            "suspicious QR text"
        )


    # ========================================================
    # PREFIX ANALYSIS
    # ========================================================

    if len(prefix) <= 3:

        risk += 0.12

        reasons.append(
            "unusually short UPI identifier"
        )


    # Many digits in the UPI prefix
    digit_count = sum(
        char.isdigit()
        for char in prefix
    )

    if len(prefix) > 0:

        digit_ratio = (
            digit_count /
            len(prefix)
        )

        if digit_ratio > 0.65:

            risk += 0.12

            reasons.append(
                "unusual numeric pattern"
            )


    # ========================================================
    # LONG / COMPLEX IDENTIFIER
    # ========================================================

    if len(prefix) >= 18:

        risk += 0.08

        reasons.append(
            "unusually long UPI identifier"
        )


    # ========================================================
    # MERCHANT NAME CHECK
    # ========================================================

    if not merchant_name:

        risk += 0.10

        reasons.append(
            "merchant name missing"
        )


    # ========================================================
    # MERCHANT / PREFIX SIMILARITY
    # ========================================================

    if merchant_name and prefix:

        merchant_words = re.findall(
            r"[a-zA-Z]+",
            merchant
        )

        merchant_compact = "".join(
            merchant_words
        )

        prefix_compact = re.sub(
            r"[^a-z]",
            "",
            prefix
        )

        if (
            merchant_compact
            and prefix_compact
            and (
                merchant_compact[:4]
                in prefix_compact
                or
                prefix_compact[:4]
                in merchant_compact
            )
        ):

            risk -= 0.08

            reasons.append(
                "merchant and UPI identifier appear related"
            )


    # ========================================================
    # FULL UPI ID FINGERPRINT
    #
    # This makes each distinct UPI ID independently
    # identifiable without generating random risk.
    # ========================================================

    fingerprint = hashlib.sha256(
        upi_id.encode("utf-8")
    ).hexdigest()

    fingerprint_number = int(
        fingerprint[:8],
        16
    )

    # Small deterministic adjustment based on
    # the actual UPI ID.
    #
    # This is NOT random.
    #
    # The same UPI ID always gets the same adjustment.

    fingerprint_adjustment = (
        (fingerprint_number % 7)
        - 3
    ) * 0.01

    risk += fingerprint_adjustment


    # ========================================================
    # LIMIT
    # ========================================================

    risk = max(
        0.02,
        min(
            0.95,
            risk
        )
    )


    return {
        "qr_risk": risk,
        "reason": "; ".join(reasons)
            if reasons
            else "normal QR characteristics"
    }


# ============================================================
# HISTORY RECORD
# ============================================================

def create_history_record():

    return {

        "scan_count": 0,

        "genuine_count": 0,

        "suspicious_count": 0,

        "fraud_count": 0,

        "first_seen": datetime.now().isoformat(),

        "last_seen": datetime.now().isoformat(),

        "merchant_names": [],

        "qr_samples": []

    }


# ============================================================
# UPDATE HISTORY
# ============================================================

def update_history(

    history,
    upi_id,
    merchant_name,
    qr_text
):

    if not upi_id:
        return None

    key = normalize_upi_id(
        upi_id
    )

    if key not in history:

        history[key] = (
            create_history_record()
        )


    record = history[key]


    record["scan_count"] = (
        record.get(
            "scan_count",
            0
        ) + 1
    )


    record["last_seen"] = (
        datetime.now().isoformat()
    )


    # --------------------------------------------------------
    # Merchant history
    # --------------------------------------------------------

    if merchant_name:

        if merchant_name not in record[
            "merchant_names"
        ]:

            record[
                "merchant_names"
            ].append(
                merchant_name
            )


    # --------------------------------------------------------
    # QR history
    # --------------------------------------------------------

    if qr_text:

        if qr_text not in record[
            "qr_samples"
        ]:

            record[
                "qr_samples"
            ].append(
                qr_text
            )


    if len(
        record["qr_samples"]
    ) > 10:

        record[
            "qr_samples"
        ] = record[
            "qr_samples"
        ][-10:]


    return record


# ============================================================
# HISTORY RISK
# ============================================================

def calculate_history_risk(
    record
):

    # --------------------------------------------------------
    # Never seen before
    # --------------------------------------------------------

    if not record:

        return 0.25


    scans = record.get(
        "scan_count",
        0
    )

    genuine = record.get(
        "genuine_count",
        0
    )

    suspicious = record.get(
        "suspicious_count",
        0
    )

    fraud = record.get(
        "fraud_count",
        0
    )


    # --------------------------------------------------------
    # Previous fraud
    # --------------------------------------------------------

    if fraud > 0:

        fraud_ratio = (
            fraud /
            max(scans, 1)
        )

        return min(
            0.95,
            0.70 +
            fraud_ratio * 0.25
        )


    # --------------------------------------------------------
    # Previous suspicious results
    # --------------------------------------------------------

    if suspicious > 0:

        suspicious_ratio = (
            suspicious /
            max(scans, 1)
        )

        return min(
            0.75,
            0.45 +
            suspicious_ratio * 0.25
        )


    # --------------------------------------------------------
    # Repeated clean history
    # --------------------------------------------------------

    if genuine >= 10:

        return 0.04


    if genuine >= 5:

        return 0.08


    if genuine >= 2:

        return 0.15


    if scans >= 1:

        return 0.22


    return 0.25


# ============================================================
# MODEL FEATURES
# ============================================================

def create_model_features(

    qr_characteristics,
    history_record

):

    qr_risk = qr_characteristics[
        "qr_risk"
    ]


    scan_count = 0

    if history_record:

        scan_count = history_record.get(
            "scan_count",
            0
        )


    # --------------------------------------------------------
    # IMPORTANT
    #
    # The saved model expects:
    #
    # handle_similarity_score
    # handle_transaction_history
    #
    # NO amount.
    # --------------------------------------------------------

    features = {

        "handle_similarity_score":
            qr_risk,

        "handle_transaction_history":
            min(
                scan_count,
                5
            )

    }


    return features


# ============================================================
# FINAL FRAUD PROBABILITY
# ============================================================

def calculate_final_probability(

    ml_probability,
    qr_probability,
    history_probability

):

    # --------------------------------------------------------
    # WEIGHTS
    #
    # QR characteristics = 55%
    # Past history       = 30%
    # ML model           = 15%
    #
    # AMOUNT             = 0%
    # --------------------------------------------------------

    final_probability = (

        qr_probability * 0.55

        +

        history_probability * 0.30

        +

        ml_probability * 0.15

    )


    return max(
        0.0,
        min(
            1.0,
            final_probability
        )
    )


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(
    probability
):

    percentage = (
        probability * 100
    )


    if percentage < 30:

        return "GENUINE"


    if percentage < 70:

        return "SUSPICIOUS"


    return "HIGH RISK"


# ============================================================
# UPDATE RESULT HISTORY
# ============================================================

def save_result_to_history(

    record,
    risk_level

):

    if not record:
        return


    if risk_level == "HIGH RISK":

        record["fraud_count"] = (
            record.get(
                "fraud_count",
                0
            ) + 1
        )


    elif risk_level == "SUSPICIOUS":

        record["suspicious_count"] = (
            record.get(
                "suspicious_count",
                0
            ) + 1
        )


    else:

        record["genuine_count"] = (
            record.get(
                "genuine_count",
                0
            ) + 1
        )


# ============================================================
# HOME
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)

def home():

    return jsonify({

        "status":
            "UPI Guard ML Server Running",

        "fraud_calculation":
            "QR + UPI history + ML",

        "amount_used":
            False,

        "history_enabled":
            True,

        "model_features":
            FEATURES

    })


# ============================================================
# PREDICT
# ============================================================

@app.route(
    "/predict",
    methods=["POST"]
)

def predict():

    try:

        data = request.get_json(
            silent=True
        )


        if not data:

            return jsonify({

                "success":
                    False,

                "error":
                    "No JSON data received"

            }), 400


        qr_text = data.get(
            "qr_text",
            ""
        )


        if not qr_text:

            return jsonify({

                "success":
                    False,

                "error":
                    "qr_text is missing"

            }), 400


        # ====================================================
        # PARSE QR
        # ====================================================

        parsed = parse_upi_qr(
            qr_text
        )


        upi_id = normalize_upi_id(
            parsed["upi_id"]
        )

        merchant_name = (
            parsed["merchant_name"]
        )

        amount = parsed[
            "amount"
        ]


        print(
            "\n========================================"
        )

        print(
            "NEW QR SCAN"
        )

        print(
            "========================================"
        )

        print(
            "UPI ID:",
            upi_id
        )

        print(
            "Merchant:",
            merchant_name
        )

        print(
            "Amount:",
            amount,
            "(DISPLAY ONLY)"
        )


        # ====================================================
        # LOAD HISTORY
        # ====================================================

        history = load_history()


        previous_record = history.get(
            upi_id
        )


        if previous_record:

            print(
                "Previous scans:",
                previous_record.get(
                    "scan_count",
                    0
                )
            )

            print(
                "Previous genuine:",
                previous_record.get(
                    "genuine_count",
                    0
                )
            )

            print(
                "Previous suspicious:",
                previous_record.get(
                    "suspicious_count",
                    0
                )
            )

            print(
                "Previous fraud:",
                previous_record.get(
                    "fraud_count",
                    0
                )

            )

        else:

            print(
                "Previous history: NEW UPI ID"
            )


        # ====================================================
        # QR ANALYSIS
        # ====================================================

        qr_characteristics = (
            calculate_qr_characteristics(

                upi_id,

                merchant_name

            )
        )


        qr_probability = (
            qr_characteristics[
                "qr_risk"
            ]
        )


        print(
            "QR risk:",
            round(
                qr_probability * 100,
                2
            ),
            "%"
        )


        print(
            "QR reason:",
            qr_characteristics[
                "reason"
            ]
        )


        # ====================================================
        # HISTORY ANALYSIS
        # ====================================================

        history_probability = (
            calculate_history_risk(

                previous_record

            )
        )


        print(
            "History risk:",
            round(
                history_probability * 100,
                2
            ),
            "%"
        )


        # ====================================================
        # MODEL FEATURES
        # ====================================================

        feature_values = (
            create_model_features(

                qr_characteristics,

                previous_record

            )
        )


        print(
            "Model features:",
            feature_values
        )


        input_df = pd.DataFrame(

            [feature_values],

            columns=FEATURES

        )


        # ====================================================
        # ML PREDICTION
        # ====================================================

        ml_probability = (
            model.predict_proba(
                input_df
            )[0][1]
        )


        print(
            "ML probability:",
            round(
                ml_probability * 100,
                2
            ),
            "%"
        )


        # ====================================================
        # FINAL SCORE
        # ====================================================

        final_probability = (
            calculate_final_probability(

                ml_probability,

                qr_probability,

                history_probability

            )
        )


        fraud_percentage = round(

            final_probability * 100,

            2

        )


        # ====================================================
        # RISK LEVEL
        # ====================================================

        risk_level = get_risk_level(

            final_probability

        )


        # ====================================================
        # UPDATE HISTORY
        # ====================================================

        current_record = (
            update_history(

                history,

                upi_id,

                merchant_name,

                qr_text

            )
        )


        save_result_to_history(

            current_record,

            risk_level

        )


        save_history(
            history
        )


        # ====================================================
        # FINAL LOG
        # ====================================================

        print(
            "----------------------------------------"
        )

        print(
            "FINAL FRAUD:",
            fraud_percentage,
            "%"
        )

        print(
            "RISK:",
            risk_level
        )

        print(
            "AMOUNT USED:",
            "NO"
        )

        print(
            "========================================\n"
        )


        # ====================================================
        # RESPONSE TO ANDROID
        # ====================================================

        return jsonify({

            "success":
                True,

            "upi_id":
                upi_id,

            "merchant_name":
                merchant_name,

            # Sent only for display.
            # NOT used for fraud calculation.
            "amount":
                amount,

            "fraud_probability":
                fraud_percentage,

            "risk_level":
                risk_level,

            "history_scan_count":
                current_record.get(
                    "scan_count",
                    0
                ) if current_record else 0,

            "error":
                None

        })


    except Exception as e:

        print(
            "\nPREDICTION ERROR:",
            str(e)
        )


        return jsonify({

            "success":
                False,

            "upi_id":
                None,

            "merchant_name":
                None,

            "amount":
                None,

            "fraud_probability":
                None,

            "risk_level":
                None,

            "error":
                str(e)

        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print(
        "\n========================================"
    )

    print(
        "UPI GUARD FINAL SERVER"
    )

    print(
        "========================================"
    )

    print(
        "QR analysis       : ENABLED"
    )

    print(
        "UPI ID analysis   : ENABLED"
    )

    print(
        "Past history      : ENABLED"
    )

    print(
        "Amount influence  : DISABLED"
    )

    print(
        "Server:"
    )

    print(
        "http://0.0.0.0:5000"
    )

    print(
        "========================================\n"
    )


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )