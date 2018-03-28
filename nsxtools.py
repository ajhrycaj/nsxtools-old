from flask import Flask, render_template, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html',name='Main Page')

@app.route('/contact')
def contact():
    return 'Contact info here'

@app.route('/listnsxmanager')
def getNsxManagerFromDB():
    return 'test'
app.add_url_rule('/listnsxmanager','listnsxmanager',getNsxManagerFromDB)

@app.route('/addnsxmanager')
def addNsxManagerToDB():
    return 'Add NSX Manager'
app.add_url_rule('/addnsxmanager','addnsxmanager',addNsxManagerToDB)

if __name__ == '__main__':
    app.run()
