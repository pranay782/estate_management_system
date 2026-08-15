from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file
)
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from datetime import datetime
import os, io, csv, bcrypt

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "estatepro-development-secret")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
db = client["real_estate_database"]

# Existing collections
admin = db["admin"]
users = db["users"]
properties = db["properties"]
clients = db["clients"]
agents = db["agents"]
inquiries = db["inquiries"]
appointments = db["appointments"]
favorites = db["favorites"]
transactions = db["transactions"]
receipts = db["receipts"]

UPLOAD_DIR = os.path.join("static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED = {"png", "jpg", "jpeg", "webp"}


def mongo_ok():
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False


def normalize_id(value):
    """The existing DB uses IDs such as PROP001 and ADM010.
    This helper also supports ObjectId-style IDs."""
    return str(value) if value is not None else ""


def find_by_id(collection, value):
    if not value:
        return None
    value = str(value)
    doc = collection.find_one({"_id": value})
    if doc:
        return doc
    try:
        from bson import ObjectId
        return collection.find_one({"_id": ObjectId(value)})
    except Exception:
        return None


def delete_by_id(collection, value):
    value = str(value)
    result = collection.delete_one({"_id": value})
    if result.deleted_count:
        return result
    try:
        from bson import ObjectId
        return collection.delete_one({"_id": ObjectId(value)})
    except Exception:
        return result


def set_by_id(collection, value, update):
    value = str(value)
    result = collection.update_one({"_id": value}, update)
    if result.matched_count:
        return result
    try:
        from bson import ObjectId
        return collection.update_one({"_id": ObjectId(value)}, update)
    except Exception:
        return result


def login_required():
    return "user_id" in session


def admin_required():
    return login_required() and session.get("role") == "Admin"


def staff_required():
    return login_required() and session.get("role") in {"Admin", "Agent"}


def parse_float(value, default=0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def next_code(prefix, collection):
    try:
        count = collection.count_documents({})
    except Exception:
        count = 0
    return f"{prefix}{count + 1:03d}"


def password_matches(password, stored):
    if not stored:
        return False
    if isinstance(stored, str):
        stored = stored.encode()
    try:
        return bcrypt.checkpw(password.encode(), stored)
    except Exception:
        return False


def create_default_admin():
    existing = users.find_one({"role": "Admin"})
    if existing:
        return

    password_hash = bcrypt.hashpw(
        b"admin123", bcrypt.gensalt()
    )
    users.insert_one({
        "_id": "ADM001",
        "username": "admin",
        "name": "EstatePro Administrator",
        "email": "admin@estatepro.com",
        "phone": "+91 98765 40010",
        "password_hash": password_hash,
        "role": "Admin",
        "status": "Active",
        "permissions": [
            "users", "properties", "agents", "clients",
            "inquiries", "appointments", "reports"
        ],
        "createdAt": datetime.utcnow(),
        "lastLogin": None
    })
    print("Default admin created: admin@estatepro.com / admin123")


@app.context_processor
def globals():
    return {
        "logged_user": session.get("username"),
        "logged_name": session.get("name"),
        "logged_role": session.get("role")
    }


@app.route("/")
def home():
    try:
        featured = list(
            properties.find({"status": "Available"})
            .sort("postedDate", -1).limit(6)
        )
        stats = {
            "properties": properties.count_documents({}),
            "available": properties.count_documents({"status": "Available"}),
            "agents": agents.count_documents({}),
            "clients": clients.count_documents({})
        }
    except Exception:
        featured, stats = [], {"properties": 0, "available": 0, "agents": 0, "clients": 0}
    return render_template("index.html", featured=featured, stats=stats)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not name or not email or len(password) < 6:
            flash("Please complete all fields. Password must contain at least 6 characters.", "danger")
            return redirect(url_for("register"))

        if users.find_one({"$or": [{"username": username}, {"email": email}]}):
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))

        users.insert_one({
            "_id": next_code("USR", users),
            "username": username,
            "name": name,
            "email": email,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            "role": "Client",
            "status": "Active",
            "createdAt": datetime.utcnow()
        })
        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        user = users.find_one({
            "$or": [
                {"username": identity},
                {"email": identity.lower()}
            ]
        })

        if not user:
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html")

        if user.get("status", "Active") != "Active":
            flash("Your account is inactive. Contact an administrator.", "danger")
            return render_template("login.html")

        if not password_matches(password, user.get("password_hash")):
            # A bcrypt hash may also be stored under `password`.
            if not password_matches(password, user.get("password")):
                flash("Invalid username/email or password.", "danger")
                return render_template("login.html")

        session["user_id"] = normalize_id(user.get("_id"))
        session["username"] = user.get("username") or user.get("email", "").split("@")[0]
        session["name"] = user.get("name") or session["username"]
        session["role"] = user.get("role", "Client")

        set_by_id(users, user.get("_id"), {"$set": {"lastLogin": datetime.utcnow()}})

        if session["role"] == "Admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    if admin_required():
        return redirect(url_for("admin_dashboard"))

    stats = {
        "properties": properties.count_documents({}),
        "available": properties.count_documents({"status": "Available"}),
        "sold": properties.count_documents({"status": "Sold"}),
        "rented": properties.count_documents({"status": "Rented"}),
        "clients": clients.count_documents({}),
        "agents": agents.count_documents({}),
        "inquiries": inquiries.count_documents({}),
        "appointments": appointments.count_documents({})
    }
    recent = list(properties.find().sort("postedDate", -1).limit(5))
    return render_template("dashboard.html", stats=stats, recent=recent)


# -------------------- ADMIN --------------------

@app.route("/admin")
def admin_dashboard():
    if not admin_required():
        flash("Admin access required.", "danger")
        return redirect(url_for("login"))

    stats = {
        "users": users.count_documents({}),
        "clients": clients.count_documents({}),
        "agents": agents.count_documents({}),
        "properties": properties.count_documents({}),
        "available": properties.count_documents({"status": "Available"}),
        "sold": properties.count_documents({"status": "Sold"}),
        "rented": properties.count_documents({"status": "Rented"}),
        "inquiries": inquiries.count_documents({}),
        "appointments": appointments.count_documents({})
    }
    recent_properties = list(properties.find().sort("postedDate", -1).limit(8))
    recent_inquiries = list(inquiries.find().sort("createdAt", -1).limit(5))
    recent_appointments = list(appointments.find().sort("createdAt", -1).limit(5))
    return render_template(
        "admin.html",
        stats=stats,
        recent_properties=recent_properties,
        recent_inquiries=recent_inquiries,
        recent_appointments=recent_appointments
    )


@app.route("/admin/users")
def admin_users():
    if not admin_required():
        return redirect(url_for("login"))
    all_users = list(users.find({}, {"password_hash": 0, "password": 0}).sort("createdAt", -1))
    return render_template("admin_users.html", users=all_users)


@app.route("/admin/user/role/<user_id>", methods=["POST"])
def admin_change_role(user_id):
    if not admin_required():
        return redirect(url_for("login"))
    if user_id == session.get("user_id"):
        flash("You cannot change your own Admin role.", "danger")
        return redirect(url_for("admin_users"))
    role = request.form.get("role")
    if role not in {"Client", "Agent", "Admin"}:
        flash("Invalid role.", "danger")
    else:
        set_by_id(users, user_id, {"$set": {"role": role}})
        flash("User role updated.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/status/<user_id>", methods=["POST"])
def admin_change_status(user_id):
    if not admin_required():
        return redirect(url_for("login"))
    if user_id == session.get("user_id"):
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("admin_users"))
    user = find_by_id(users, user_id)
    if user:
        new_status = "Inactive" if user.get("status", "Active") == "Active" else "Active"
        set_by_id(users, user_id, {"$set": {"status": new_status}})
        flash(f"User status changed to {new_status}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/delete/<user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if not admin_required():
        return redirect(url_for("login"))
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_users"))
    delete_by_id(users, user_id)
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/properties")
def admin_properties():
    if not admin_required():
        return redirect(url_for("login"))
    return render_template(
        "admin_properties.html",
        properties=list(properties.find().sort("postedDate", -1))
    )


@app.route("/admin/property/delete/<property_id>", methods=["POST"])
def admin_delete_property(property_id):
    if not admin_required():
        return redirect(url_for("login"))
    delete_by_id(properties, property_id)
    flash("Property deleted.", "success")
    return redirect(url_for("admin_properties"))


@app.route("/admin/inquiries")
def admin_inquiries():
    if not admin_required():
        return redirect(url_for("login"))
    return render_template(
        "admin_inquiries.html",
        inquiries=list(inquiries.find().sort("createdAt", -1))
    )


@app.route("/admin/inquiry/status/<inquiry_id>", methods=["POST"])
def admin_inquiry_status(inquiry_id):
    if not admin_required():
        return redirect(url_for("login"))
    status = request.form.get("status")
    allowed = ["New", "Contacted", "Site Visit", "Negotiation", "Closed", "Cancelled"]
    if status in allowed:
        set_by_id(inquiries, inquiry_id, {"$set": {"status": status}})
        if status == "Closed":
            inquiry = find_by_id(inquiries, inquiry_id)
            if inquiry and inquiry.get("propertyId"):
                set_by_id(properties, inquiry["propertyId"], {"$set": {"status": "Sold"}})
        flash("Inquiry status updated.", "success")
    return redirect(url_for("admin_inquiries"))


@app.route("/admin/appointments")
def admin_appointments():
    if not admin_required():
        return redirect(url_for("login"))
    return render_template(
        "admin_appointments.html",
        appointments=list(appointments.find().sort("createdAt", -1))
    )


@app.route("/admin/appointment/status/<appointment_id>", methods=["POST"])
def admin_appointment_status(appointment_id):
    if not admin_required():
        return redirect(url_for("login"))
    status = request.form.get("status")
    if status in ["Pending", "Confirmed", "Completed", "Cancelled"]:
        set_by_id(appointments, appointment_id, {"$set": {"status": status}})
        flash("Appointment status updated.", "success")
    return redirect(url_for("admin_appointments"))


@app.route("/admin/reports/properties.csv")
def admin_property_csv():
    if not admin_required():
        return redirect(url_for("login"))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Property ID", "Title", "Type", "Listing", "Price",
        "City", "Bedrooms", "Bathrooms", "Area SqFt", "Status"
    ])
    for p in properties.find():
        loc = p.get("location", {})
        if isinstance(loc, dict):
            city = loc.get("city", "")
        else:
            city = p.get("city", "")
        details = p.get("details", {}) if isinstance(p.get("details"), dict) else {}
        writer.writerow([
            p.get("propertyId", p.get("_id")),
            p.get("title", ""),
            p.get("propertyType", ""),
            p.get("listingType", ""),
            p.get("price", 0),
            city,
            details.get("bedrooms", p.get("bedrooms", "")),
            details.get("bathrooms", p.get("bathrooms", "")),
            details.get("areaSqFt", p.get("areaSqFt", "")),
            p.get("status", "")
        ])
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        download_name="estatepro_properties.csv",
        as_attachment=True,
        mimetype="text/csv"
    )


# -------------------- PROPERTIES --------------------

@app.route("/properties")
def property_list():
    q = request.args.get("q", "").strip()
    ptype = request.args.get("propertyType", "")
    listing = request.args.get("listingType", "")
    status = request.args.get("status", "")
    max_price = request.args.get("max_price", "")

    query = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"propertyId": {"$regex": q, "$options": "i"}},
            {"location.city": {"$regex": q, "$options": "i"}},
            {"location.area": {"$regex": q, "$options": "i"}},
            {"city": {"$regex": q, "$options": "i"}},
            {"location": {"$regex": q, "$options": "i"}}
        ]
    if ptype:
        query["propertyType"] = ptype
    if listing:
        query["listingType"] = listing
    if status:
        query["status"] = status
    if max_price:
        price = parse_float(max_price, None)
        if price is not None:
            query["price"] = {"$lte": price}

    items = list(properties.find(query).sort("postedDate", -1))
    return render_template("properties.html", properties=items, filters=request.args)


@app.route("/properties/<property_id>")
def property_detail(property_id):
    p = find_by_id(properties, property_id)
    if not p:
        return render_template("404.html"), 404
    return render_template("property_detail.html", property=p)


@app.route("/properties/add", methods=["GET", "POST"])
def add_property():
    if not staff_required():
        flash("Only Admin or Agent can add properties.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        location = {
            "address": request.form.get("address", ""),
            "area": request.form.get("area", ""),
            "city": request.form.get("city", ""),
            "state": request.form.get("state", ""),
            "country": request.form.get("country", "India"),
            "pincode": request.form.get("pincode", "")
        }
        details = {
            "bedrooms": parse_int(request.form.get("bedrooms")),
            "bathrooms": parse_int(request.form.get("bathrooms")),
            "areaSqFt": parse_float(request.form.get("areaSqFt")),
            "floor": parse_int(request.form.get("floor")),
            "totalFloors": parse_int(request.form.get("totalFloors")),
            "furnished": request.form.get("furnished", "Unfurnished"),
            "parking": request.form.get("parking", "No") == "Yes"
        }

        data = {
            "_id": request.form.get("propertyId", "").strip() or next_code("PROP", properties),
            "propertyId": request.form.get("propertyId", "").strip() or next_code("PROP", properties),
            "title": request.form.get("title", "").strip(),
            "description": request.form.get("description", "").strip(),
            "propertyType": request.form.get("propertyType", "Apartment"),
            "listingType": request.form.get("listingType", "Sale"),
            "status": request.form.get("status", "Available"),
            "price": parse_float(request.form.get("price")),
            "currency": "INR",
            "maintenance": parse_float(request.form.get("maintenance")),
            "securityDeposit": parse_float(request.form.get("securityDeposit")),
            "negotiable": request.form.get("negotiable") == "Yes",
            "location": location,
            "details": details,
            "amenities": [x.strip() for x in request.form.get("amenities", "").split(",") if x.strip()],
            "images": [],
            "ownerId": request.form.get("ownerId", session.get("user_id")),
            "agentId": request.form.get("agentId", session.get("user_id")),
            "verified": session.get("role") == "Admin",
            "featured": request.form.get("featured") == "Yes",
            "postedDate": datetime.utcnow(),
            "lastUpdated": datetime.utcnow()
        }

        file = request.files.get("image")
        if file and file.filename:
            ext = file.filename.rsplit(".", 1)[-1].lower()
            if ext in ALLOWED:
                filename = f"{int(datetime.utcnow().timestamp())}_{secure_filename(file.filename)}"
                file.save(os.path.join(UPLOAD_DIR, filename))
                data["images"] = [f"/static/uploads/{filename}"]

        try:
            properties.insert_one(data)
            flash("Property added successfully.", "success")
            return redirect(url_for("property_list"))
        except Exception as exc:
            flash(f"Could not add property: {exc}", "danger")

    return render_template("add_property.html")


@app.route("/properties/delete/<property_id>", methods=["POST"])
def delete_property(property_id):
    if not staff_required():
        return redirect(url_for("login"))
    delete_by_id(properties, property_id)
    flash("Property deleted.", "success")
    return redirect(url_for("property_list"))


# -------------------- CLIENTS / AGENTS --------------------

@app.route("/clients-agents")
def clients_agents():
    if not staff_required():
        return redirect(url_for("dashboard"))
    return render_template(
        "clients_agents.html",
        clients=list(clients.find().sort("createdAt", -1)),
        agents=list(agents.find().sort("createdAt", -1))
    )


@app.route("/client/add", methods=["POST"])
def add_client():
    if not staff_required():
        return redirect(url_for("dashboard"))
    clients.insert_one({
        "_id": next_code("CLI", clients),
        "clientId": next_code("CLI", clients),
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "contact": request.form.get("contact"),
        "budget": parse_float(request.form.get("budget")),
        "preferredLocation": request.form.get("preferredLocation"),
        "propertyType": request.form.get("propertyType"),
        "bedrooms": parse_int(request.form.get("bedrooms")),
        "requirementType": request.form.get("requirementType", "Buy"),
        "status": "Active",
        "createdAt": datetime.utcnow()
    })
    flash("Client added.", "success")
    return redirect(url_for("clients_agents"))


@app.route("/agent/add", methods=["POST"])
def add_agent():
    if not admin_required():
        return redirect(url_for("dashboard"))
    agents.insert_one({
        "_id": next_code("AGT", agents),
        "agentId": next_code("AGT", agents),
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "contact": request.form.get("contact"),
        "region": request.form.get("region"),
        "experienceYears": parse_int(request.form.get("experienceYears")),
        "specialization": request.form.get("specialization"),
        "status": "Active",
        "createdAt": datetime.utcnow()
    })
    flash("Agent added.", "success")
    return redirect(url_for("clients_agents"))


@app.route("/match/<client_id>")
def match_client(client_id):
    c = find_by_id(clients, client_id)
    if not c:
        return redirect(url_for("clients_agents"))

    query = {"status": "Available", "price": {"$lte": c.get("budget", float("inf"))}}
    if c.get("propertyType"):
        query["propertyType"] = c["propertyType"]
    if c.get("bedrooms"):
        query["$or"] = [
            {"details.bedrooms": {"$gte": c["bedrooms"]}},
            {"bedrooms": {"$gte": c["bedrooms"]}}
        ]
    if c.get("preferredLocation"):
        query["$or"] = [
            {"location.city": {"$regex": c["preferredLocation"], "$options": "i"}},
            {"location.area": {"$regex": c["preferredLocation"], "$options": "i"}},
            {"city": {"$regex": c["preferredLocation"], "$options": "i"}}
        ]
    matches = list(properties.find(query).sort("price", 1))
    return render_template("matches.html", client=c, matches=matches)


# -------------------- INQUIRIES / APPOINTMENTS --------------------

@app.route("/inquiries", methods=["GET", "POST"])
def inquiries_page():
    if not login_required():
        return redirect(url_for("login"))
    if request.method == "POST":
        inquiries.insert_one({
            "_id": next_code("INQ", inquiries),
            "inquiryId": next_code("INQ", inquiries),
            "clientId": request.form.get("clientId"),
            "propertyId": request.form.get("propertyId"),
            "agentId": request.form.get("agentId"),
            "status": "New",
            "message": request.form.get("message", ""),
            "closingPrice": None,
            "createdAt": datetime.utcnow()
        })
        flash("Inquiry created.", "success")
        return redirect(url_for("inquiries_page"))
    return render_template(
        "inquiries.html",
        inquiries=list(inquiries.find().sort("createdAt", -1)),
        clients=list(clients.find()),
        properties=list(properties.find({"status": "Available"})),
        agents=list(agents.find())
    )


@app.route("/inquiry/status/<inquiry_id>", methods=["POST"])
def update_inquiry(inquiry_id):
    if not login_required():
        return redirect(url_for("login"))
    status = request.form.get("status")
    allowed = ["New", "Contacted", "Site Visit", "Negotiation", "Closed", "Cancelled"]
    if status in allowed:
        set_by_id(inquiries, inquiry_id, {"$set": {"status": status}})
        if status == "Closed":
            iq = find_by_id(inquiries, inquiry_id)
            if iq and iq.get("propertyId"):
                set_by_id(properties, iq["propertyId"], {"$set": {"status": "Sold"}})
        flash("Inquiry updated.", "success")
    return redirect(url_for("inquiries_page"))


@app.route("/appointments", methods=["GET", "POST"])
def appointments_page():
    if not login_required():
        return redirect(url_for("login"))
    if request.method == "POST":
        appointments.insert_one({
            "_id": next_code("APT", appointments),
            "appointmentId": next_code("APT", appointments),
            "clientId": request.form.get("clientId"),
            "agentId": request.form.get("agentId"),
            "propertyId": request.form.get("propertyId"),
            "date": request.form.get("date"),
            "time": request.form.get("time"),
            "status": "Pending",
            "notes": request.form.get("notes", ""),
            "createdAt": datetime.utcnow()
        })
        flash("Appointment requested.", "success")
        return redirect(url_for("appointments_page"))
    return render_template(
        "appointments.html",
        appointments=list(appointments.find().sort("createdAt", -1)),
        clients=list(clients.find()),
        agents=list(agents.find()),
        properties=list(properties.find({"status": "Available"}))
    )


@app.route("/appointment/status/<appointment_id>", methods=["POST"])
def appointment_status(appointment_id):
    if not login_required():
        return redirect(url_for("login"))
    status = request.form.get("status")
    if status in ["Pending", "Confirmed", "Completed", "Cancelled"]:
        set_by_id(appointments, appointment_id, {"$set": {"status": status}})
    return redirect(url_for("appointments_page"))


# -------------------- REPORT / API --------------------

@app.route("/reports/properties.csv")
def property_csv():
    if not staff_required():
        return redirect(url_for("dashboard"))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Property ID", "Title", "Type", "Listing", "Price", "City", "Bedrooms", "Bathrooms", "Area SqFt", "Status"])

    for p in properties.find():
        loc = p.get("location", {}) if isinstance(p.get("location"), dict) else {}
        details = p.get("details", {}) if isinstance(p.get("details"), dict) else {}
        writer.writerow([
            p.get("propertyId", p.get("_id")),
            p.get("title"),
            p.get("propertyType"),
            p.get("listingType"),
            p.get("price"),
            loc.get("city", p.get("city", "")),
            details.get("bedrooms", p.get("bedrooms", "")),
            details.get("bathrooms", p.get("bathrooms", "")),
            details.get("areaSqFt", p.get("areaSqFt", "")),
            p.get("status")
        ])

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        download_name="estatepro_properties.csv",
        as_attachment=True,
        mimetype="text/csv"
    )


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "properties": properties.count_documents({}),
        "available": properties.count_documents({"status": "Available"}),
        "sold": properties.count_documents({"status": "Sold"}),
        "rented": properties.count_documents({"status": "Rented"}),
        "clients": clients.count_documents({}),
        "agents": agents.count_documents({}),
        "inquiries": inquiries.count_documents({}),
        "appointments": appointments.count_documents({})
    })


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    print("EstatePro running at http://127.0.0.1:5000")
    print("MongoDB:", "CONNECTED" if mongo_ok() else "NOT CONNECTED")
    if mongo_ok():
        create_default_admin()
    app.run(host="127.0.0.1", port=5000, debug=True)
