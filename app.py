# This is the main runnable flask entrypoint for the program

from datetime import date, datetime

from Crypto.Random import get_random_bytes
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, ForeignKey
from sqlalchemy.orm import relationship

from werkzeug.exceptions import NotFound

import hashlib

# Creating a FlaskForm to manage CSRF properly
class NameForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

# global variables
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)
app.secret_key = 'your_secret_key'  # Required for CSRF protection
csrf = CSRFProtect(app)  # Enable CSRF Protection

accountID = int()
accountType = str()


# Intialise database
db = SQLAlchemy(app)

# Create Database Models (tables)
class DBAccounts(db.Model):
    accountID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    firstname = db.Column(db.String(200), nullable=False)
    lastname = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(1), nullable=False) # Value "0" means a user. Value "1" means an admin

    orderDatabase_rel = db.relationship('DBOrders', backref='accountIdenfy')

    def __repr__(self):
        return f'<Account {self.username}>'

class DBProducts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(1000))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

    productIDProductOrder_rel = db.relationship('DBProductOrders', backref='productIdenfyInTable')  

    # Function returning string when something added
    def __repr__(self):
        return f'<Product {self.name}>'

class DBOrders(db.Model):
    orderID = db.Column(db.Integer, primary_key=True)
    accountID = db.Column(db.Integer, db.ForeignKey(DBAccounts.accountID), nullable=False)
    total = db.Column(db.Float, nullable=False)
    nameTo = db.Column(db.String(100),nullable=False)
    address = db.Column(db.String(500),nullable=False)
    postcode = db.Column(db.String(10),nullable=False)
    
    orderIDProductOrder_rel = db.relationship('DBProductOrders', backref='orderIdenfyInTable')

    # Function returning string when something added
    def __repr__(self):
        return f'<Order {self.orderID}>'

class DBProductOrders(db.Model):
    productOrderId = db.Column(db.Integer, primary_key=True)
    orderIDForeign = db.Column(db.Integer, db.ForeignKey(DBOrders.orderID))
    productIDForeign = db.Column(db.Integer, db.ForeignKey(DBProducts.id))
    productQuantity = db.Column(db.Integer, nullable=False)
    subtotal = db.Column(db.Float, nullable=False)
    # Function returning string when something added

    def __repr__(self):
        return f'<Product {self.productIDForeign}, from order {self.orderIDForeign}>'

# Define Classes
class Basket():
    productIDs = []
    quantities = []
    total = float

    def __init__(self):
        self.total = 0.00
    def Add_Product(self,id,quantity):
        inBasket = self.CheckIfInBasket(id)
        if inBasket != -1:  
            self.quantities[inBasket]+=int(quantity)
        else:
            self.productIDs.append(id)
            self.quantities.append(int(quantity))

        product = DBProducts.query.get_or_404(id)
        self.total+=product.price*float(quantity)
    def CheckIfInBasket(self,id):
        count = 0
        for productID in self.productIDs:
            if productID == id:
                return count
            else:
                count+=1
        return -1
    def Remove_Product(self,id):
        for i in range(0,self.productIDs.__len__()):
            if int(self.productIDs[i]) == int(id):
                id=self.productIDs.pop(i)
                quantity=self.quantities.pop(i)
                product = DBProducts.query.get_or_404(int(id))
                self.total=self.total-(product.price*float(quantity))

class Order():
    products = []
    names = []
    total = float
    orderID = int

    def __init__(self):
        self.total = 0.00
        self.names = []
    def findOrder(self,orderID):
        self.products = DBProductOrders.query.filter_by(orderIDForeign=orderID).all()
        for i in range(0,self.products.__len__()):
            self.names.append(DBProducts.query.get_or_404(self.products[i].productIDForeign).name)
        self.total = DBOrders.query.get_or_404(orderID).total
        self.orderID = orderID
        

# Define Functions
def CheckIfViablePassword(password, confirmpassword):
    # checks if the password is 10+ characters including both cases, digits and special characters
    #   returning true if all conditions are met else returns false.

    viable = False
    if password == confirmpassword:
        if len(password) >= 10:
            digit = False
            lower = False
            upper = False
            symbol = False

            for char in password:
                asc = ord(char)
                if asc >= 48 and asc <= 57:
                    digit = True
                elif asc >= 65 and asc <= 90:
                    upper = True
                elif asc >= 97 and asc <= 122:
                    lower = True
                else:
                    symbol = True
            if digit and lower and upper and symbol:
                viable = True
    if viable:
        return True
    else:
        return False

def CheckIfViableEmail(email):
    # checks if the email has an '@' and a '.' returning true if all conditions are met else returns false.
    at = False
    dot = False

    for char in email:
        asc = ord(char)
        if asc == 64:
            at = True
        elif asc == 46:
            dot = True
    if at and dot:
        return True
    else:
        return False

def AES_with_ECB_ENCODE(plainText):
    hexKey = DBAccounts.query.get_or_404(accountID).salt
    intKey = []
    for byteNum in range(0,len(hexKey),2):
        byte = hexKey[byteNum] + hexKey[byteNum+1]
        intKey.append(int(byte,16))

    count = 0
    cipherText = ""

    for character in plainText:
        intChar = ord(character)
        XOR = intChar ^ intKey[count]
        count+=1
        if count >= 16:
            count=0
        cipherText += chr(XOR)
    return cipherText 

def AES_with_ECB_ENCODE_salt(plainText,salt):
    hexKey = salt.hex()
    intKey = []
    for byteNum in range(0,len(hexKey),2):
        byte = hexKey[byteNum] + hexKey[byteNum+1]
        intKey.append(int(byte,16))

    count = 0
    cipherText = ""

    for character in plainText:
        intChar = ord(character)
        XOR = intChar ^ intKey[count]
        count+=1
        if count >= 16:
            count=0
        cipherText += chr(XOR)
    return cipherText 

def AES_with_ECB_DECODE(cipherText):
    hexKey = DBAccounts.query.get_or_404(accountID).salt
    intKey = []
    for byteNum in range(0,len(hexKey),2):
        byte = hexKey[byteNum] + hexKey[byteNum+1]
        intKey.append(int(byte,16))

    count = 0
    plainText = ""

    for character in cipherText:
        intChar = ord(character)
        XOR = intChar ^ intKey[count]
        count+=1
        if count >= 16:
            count=0
        plainText += chr(XOR)
    return plainText

# Define POST Request method
@app.after_request
def apply_caching(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "media-src 'self'; "
        "manifest-src 'self'; "
        "worker-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.set_cookie('username', 'flask', httponly=True, samesite='Strict')
    return response


# routes here
@app.route("/", methods=['GET', 'POST'])
def index():
    global accountID
    global accountType
    form = NameForm()

    if request.method == "POST":
        if form.validate_on_submit():
            if accountType == "1":

                accountID = -1
                accountType = ""
                return redirect("/",form=form)
            else:
                productID = request.form['id']
                addedQuantity = request.form['quantity']

                basket.Add_Product(id=productID,quantity=addedQuantity)

                products = DBProducts.query
                return render_template("Index.html", tableData = products,form=form)
        else:
            return 'CSRF Token Missing or Invalid!'
    
    else:
        products = DBProducts.query
        return render_template("Index.html", tableData = products,form=form)

@app.route("/<int:id>", methods=['GET', 'POST'])
def productPage(id):
    selectedID = DBProducts.query.get_or_404(id)
    form = NameForm() 
    
    if request.method == "POST":
        if form.validate_on_submit():
            selectedID.name = request.form['name']
            try:
                db.session.commit()
                return redirect('/',form = form)
            except:
                return "There was an error adding this product."
        else:
            return 'CSRF Token Missing or Invalid!'
        
    else:
        for i in range(0,basket.productIDs.__len__()):
            if int(id) == int(basket.productIDs[i]):
                selectedID.quantity=selectedID.quantity-basket.quantities[i]
        return render_template("ProductPage.html",selectedID = selectedID,form=form)   

@app.route("/basket", methods=['GET', 'POST'])
def showBasket():
    form = NameForm() 

    if request.method == "POST":
        if form.validate_on_submit():
            return redirect("/shipping",form = form)
        else:
            return 'CSRF Token Missing or Invalid!'
    else:
        basketItem = []

        for i in range(0,basket.productIDs.__len__()):
            fullProduct = DBProducts.query.get_or_404(basket.productIDs[i])
            basketItem.append({
                "product": fullProduct,
                "quantityAdded": basket.quantities[i],
                "subtotals": float(basket.quantities[i])*fullProduct.price,
            })
        return render_template("Basket.html",basket=basketItem,total=basket.total,form=form)

@app.route("/delete/<int:id>", methods=['GET', 'POST'])
def deleteItem(id):
    form = NameForm() 

    basket.Remove_Product(id)  
    return redirect("/basket",form=form)

@app.route("/shipping", methods=['GET', 'POST'])
def selectshipping():
    form = NameForm() 

    if accountID == -1:
        return render_template("Login.html",error_message="Please Login before placing an order",form=form)
    else:
        if request.method == "POST":
            if form.validate_on_submit():
                nameTo = request.form["firstname"]+" "+request.form["lastname"]
                address = request.form["line1"]+";"+request.form["line2"]+";"+request.form["city"]
                postcode = request.form["postcode"]

                new_order = DBOrders(accountID=accountID,total=basket.total,nameTo=AES_with_ECB_ENCODE(nameTo),address=AES_with_ECB_ENCODE(address),postcode=AES_with_ECB_ENCODE(postcode))
                try:
                    db.session.add(new_order)
                    db.session.commit()
                except:
                    #Goes to this as needs to be signed into an account
                    basketItem = []

                    for i in range(0,basket.quantities.__len__()):
                        fullProduct = DBProducts.query.get_or_404(basket.productIDs[i])
                        basketItem.append({
                            "product": fullProduct,
                            "quantityAdded": basket.quantities[i],
                            "subtotals": float(basket.quantities[i])*fullProduct.price,
                        })
                    return render_template("Login.html",error_message="Please Login before placing an order",form=form)

                for i in range(0,basket.productIDs.__len__()):
                    product  = DBProducts.query.get_or_404(basket.productIDs[i])
                    new_productOrder = DBProductOrders(orderIDForeign=new_order.orderID,productIDForeign=product.id,productQuantity=basket.quantities[i],subtotal=float(basket.quantities[i])*product.price)
                    # push
                    try:
                        db.session.add(new_productOrder)
                        db.session.commit()
                    except:
                        return "There was an error adding this product."
            
                # Update DBProducts
                for i in range(0,basket.productIDs.__len__()):
                    product  = DBProducts.query.get_or_404(basket.productIDs[i])
                    product.quantity = product.quantity - basket.quantities[i]
                    # push
                    try:
                        db.session.add(product)
                        db.session.commit()
                    except:
                        return "There was an error adding this product."

                # Clear Basket
                basket.productIDs = []
                basket.quantities = []
                basket.total = 0.00

                return redirect("/basket",form=form)
            else:
                return 'CSRF Token Missing or Invalid!'

        else:
            return render_template("shipping.html")

@app.route("/login", methods=['GET', 'POST'])
def accessAccount():
    global accountID
    global accountType
    form = NameForm() 

    if request.method == "POST":
        if form.validate_on_submit():
            attemptedPassword = request.form["password"]
            attemptedUsername = request.form["username"]


            try:
                account = DBAccounts.query.filter_by(username=attemptedUsername).first()
                salt = bytes.fromhex(account.salt)
                attemptedPassword = str(hashlib.pbkdf2_hmac('sha256',attemptedPassword.encode(),salt,200000).hex())
                if account.password == attemptedPassword:
                    account = DBAccounts.query.filter_by(username=attemptedUsername).first()
                    accountID = account.accountID
                    accountType = AES_with_ECB_DECODE(account.type)
                    return redirect("/home",form=form)
                else:
                    return render_template("Login.html",error_message = "Username or Password incorrect",form=form)

            except NotFound:
                return render_template("Login.html",error_message = "Username or Password incorrect",form=form)
        else:
                return 'CSRF Token Missing or Invalid!'
        
    else:
        if accountID != -1:
            return redirect("/home",form=form)
        else:
            return render_template("Login.html",form=form)

@app.route("/createaccount", methods=['GET', 'POST'])
def createAccount():
        form = NameForm()

        if request.method == "POST":
            if form.validate_on_submit():
                password = CheckIfViablePassword(
                    request.form["password"], request.form["confirmPassword"]
                )
                email = CheckIfViableEmail(request.form["email"])
                if password and email:
                    usernameToAdd = request.form["username"]
                    passwordToAdd = request.form["password"]
                    firstnameToAdd = request.form["forename"]
                    lastnameToAdd = request.form["surname"]
                    emailToAdd = request.form["email"]

                    salt = os.urandom(32)
                    passwordToAdd = str(hashlib.pbkdf2_hmac('sha256', passwordToAdd.encode(), salt, 200000).hex())
                    print(passwordToAdd)
                    new_account = DBAccounts(username=usernameToAdd,password=passwordToAdd,salt=salt.hex(),email=AES_with_ECB_ENCODE_salt(emailToAdd,salt),firstname=AES_with_ECB_ENCODE_salt(firstnameToAdd,salt),lastname=AES_with_ECB_ENCODE_salt(lastnameToAdd,salt),type=AES_with_ECB_ENCODE_salt("0",salt))
                    print("object")
                    try:
                        db.session.add(new_account)
                        print("try")
                        db.session.commit()
                        print("account")
                        return redirect("/login")
                    except:
                        return "There was an error creating this account"
                else:
                    return render_template("MakeAccount.html",error_message="Please make sure all information fits the requirements",form=form)
            else:
                return 'CSRF Token Missing or Invalid!'
        else:
            return render_template("MakeAccount.html",form=form)

@app.route("/home", methods=['GET', 'POST'])
def homePages():
    global accountID
    global accountType
    form = NameForm() 

    if request.method == 'GET':
        if accountType == "1":
            return render_template("adminHome.html",form=form)
        elif accountType == "0":
            allOrders = DBOrders.query.filter_by(accountID=accountID).all()
            listOfOrders = []
            for order in allOrders:
                orderToAdd = Order()
                orderToAdd.findOrder(order.orderID)
                listOfOrders.append(orderToAdd)
            return render_template("userHome.html",listOfOrders=listOfOrders,form=form)
        else:
            return NotFound()
    elif request.method == 'POST' and accountType == "1":
        adminEmail = request.form['email']
        adminUsername = request.form['username']
        adminPassword = request.form['password']
        confirmPassword = request.form['confirmPassword']
        firstnameToAdd = request.form["forename"]
        lastnameToAdd = request.form["surname"]

        passwordValid = CheckIfViablePassword(adminPassword,confirmPassword)
        emailValid = CheckIfViableEmail(adminEmail)

        if passwordValid and emailValid:
            salt = os.urandom(32)
            passwordToAdd = str(hashlib.pbkdf2_hmac('sha256', adminPassword.encode(), salt, 200000).hex())

            new_account = DBAccounts(username=adminUsername,password=passwordToAdd,salt=salt.hex(),email=AES_with_ECB_ENCODE_salt(adminEmail,salt),firstname=AES_with_ECB_ENCODE_salt(firstnameToAdd,salt),lastname=AES_with_ECB_ENCODE_salt(lastnameToAdd,salt),type=AES_with_ECB_ENCODE_salt("1",salt))
            try:
                db.session.add(new_account)
                db.session.commit()
                return render_template("adminHome.html",form=form)
            except:
                return "There was an error creating this account"
        else:
            return render_template("MakeAccount.html",error_message="Please make sure all information fits the requirements",form=form)
    else:
        accountID = -1
        accountType = ""
        return redirect("/",form=form)

# Admin Routes Specific
@app.route("/addnewproduct", methods=['GET', 'POST'])
def newProductPage():
    form = NameForm() 
# Redirect when a specific item page is selected. Takes the product ID and returns to the new page all the information for it
    if accountType == "1":
        if request.method == "POST":
            productName = request.form['name']
            productDesc = request.form['description']
            productPrice = request.form['price']
            productQuant = request.form['quantity']
            new_product = DBProducts(name=productName,description=productDesc,quantity=productQuant,price=productPrice)

            # push
            try:
                db.session.add(new_product)
                db.session.commit()
                return redirect("/addnewproduct",form=form)
            except:
                return "There was an error adding this product."
            
        else:
            return render_template("addNewProduct.html",form=form)  
    else:
        return NotFound()

@app.route("/addnewstock", methods=['GET', 'POST'])
def addNewStock():
    form = NameForm() 

    if accountType == "1":
        if request.method == "GET":
            products = DBProducts.query
            return render_template("findProduct.html", tableData = products,form=form)
        else:
            product = DBProducts.query.get_or_404(request.form['id'])
            return redirect(url_for(
                            "addNewStockITEM",
                            id=product.id
                        ))
    else:
        return NotFound()
@app.route("/addnewstock/<int:id>", methods=['GET', 'POST'])
def addNewStockITEM(id):
    form = NameForm() 

    if accountType == "1":
        if request.method == "POST":
            product = DBProducts.query.get_or_404(id)
            product.quantity = request.form['quantity']

            try:
                db.session.add(product)
                db.session.commit()
                return redirect("/addnewstock",form=form)
            except:
                return "There was an error adding updating the stock for this product."
        else:
            product = DBProducts.query.get_or_404(id)
            return render_template("addStock.html",product=product,form=form)
    else:
        return NotFound()

@app.route("/removeproduct", methods=['GET', 'POST'])
def removeProduct():
    form = NameForm() 

    if accountType == "1":
        if request.method == "GET":
            products = DBProducts.query
            return render_template("findProductDELETE.html", tableData = products,form=form)
        else: 
            productToRemove = DBProducts.query.get_or_404(request.form['id'])
            try:
                db.session.delete(productToRemove)
                db.session.commit()
                return redirect("/removeproduct",form=form)
            except:
                return "There was an error adding updating the stock for this product."
    else:
        return NotFound()

# main here

if __name__ == "__main__":
    basket = Basket()
    accountID = -1

    app.run(host="localhost",debug=False)