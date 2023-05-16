from flask import Flask, render_template, request, url_for 
from threading import Thread, Lock
import logging
import sys 
import values 
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None


app = Flask(__name__)

@app.route('/math')
def root():
    return render_template('math.html', a=values.a,b=values.b)

def run_web():
    logging.getLogger('werkzeug').disabled = True
    app.run( debug=False, host="0.0.0.0", port=7000)
