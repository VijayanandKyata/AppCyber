import csv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///breach.db'  # Change this to your actual database URI
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Breach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entity = db.Column(db.String(255))
    year = db.Column(db.Integer)
    records = db.Column(db.String(255))
    organization_type = db.Column(db.String(255))
    methods = db.Column(db.String(255))
    url = db.Column(db.String(2048))
    time = db.Column(db.String(255))
    attacktype = db.Column(db.String(255))

    def __repr__(self):
        return f"<Breach(entity='{self.entity}', year='{self.year}', records='{self.records}', organization_type='{self.organization_type}', methods='{self.methods}', url='{self.url}', time='{self.time}', type='{self.attacktype}')>"

def load_data_from_csv():
    with app.app_context():
        db.create_all()  # Create tables
        with open('breaches.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                record = Breach(
                    entity=row[0],
                    year=int(row[1]),
                    records=row[2],
                    organization_type=row[3],
                    methods=row[4],
                    url=row[5],
                    attacktype=row[6],
                    time=row[7]
                )
                db.session.add(record)
        db.session.commit()

@app.before_first_request
def create_tables():
    db.create_all()


# Run this code to load data from CSV into your database
if __name__ == '__main__':
    load_data_from_csv()
