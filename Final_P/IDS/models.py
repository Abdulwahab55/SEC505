"""
Database Models for Alert and Metrics Tracking
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Users(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)  # Should be hashed in production
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Alert(db.Model):
    """Alert model for storing detected attacks"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    anomaly_percentage = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(20))  # Low, Medium, High, Critical
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    normal_count = db.Column(db.Integer)
    anomaly_count = db.Column(db.Integer)
    report_file = db.Column(db.String(255))  # Path to CSV report
    acknowledged = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Alert {self.attack_type} - {self.anomaly_percentage}%>'
    
    @property
    def severity_level(self):
        """Auto-calculate severity based on percentage"""
        if self.anomaly_percentage >= 75:
            return 'Critical'
        elif self.anomaly_percentage >= 50:
            return 'High'
        elif self.anomaly_percentage >= 25:
            return 'Medium'
        else:
            return 'Low'


class SystemMetrics(db.Model):
    """System performance metrics"""
    __tablename__ = 'system_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    captures_total = db.Column(db.Integer, default=0)
    processed_total = db.Column(db.Integer, default=0)
    predictions_total = db.Column(db.Integer, default=0)
    alerts_total = db.Column(db.Integer, default=0)
    capture_queue_size = db.Column(db.Integer, default=0)
    processing_queue_size = db.Column(db.Integer, default=0)
    prediction_queue_size = db.Column(db.Integer, default=0)
    processing_time_avg = db.Column(db.Float)  # Average processing time in seconds
    
    def __repr__(self):
        return f'<Metrics {self.timestamp}>'


class TrafficStatistics(db.Model):
    """Periodic traffic statistics"""
    __tablename__ = 'traffic_statistics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_flows = db.Column(db.Integer)
    normal_flows = db.Column(db.Integer)
    anomalous_flows = db.Column(db.Integer)
    top_source_ip = db.Column(db.String(50))
    top_destination_ip = db.Column(db.String(50))
    top_protocol = db.Column(db.String(20))
    avg_packet_size = db.Column(db.Float)
    
    def __repr__(self):
        return f'<TrafficStats {self.timestamp}>'


class AttackTypeMetrics(db.Model):
    """Metrics per attack type"""
    __tablename__ = 'attack_type_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    attack_type = db.Column(db.String(100), nullable=False)
    predictions_count = db.Column(db.Integer, default=0)
    normal_count = db.Column(db.Integer, default=0)
    anomaly_count = db.Column(db.Integer, default=0)
    anomaly_percentage = db.Column(db.Float)
    
    def __repr__(self):
        return f'<AttackMetrics {self.attack_type}>'


# Database initialization script
def init_database(app):
    """Initialize the database with all tables"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        print("✓ Database tables created successfully")


# Migration script for existing databases
def migrate_database():
    """Add new tables to existing database"""
    from sqlalchemy import create_engine, text
    
    # This should match your app.config['SQLALCHEMY_DATABASE_URI']
    engine = create_engine('mysql+pymysql://root:root@localhost:3306/projDB')
    
    create_tables_sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        attack_type VARCHAR(100) NOT NULL,
        source_ip VARCHAR(50),
        destination_ip VARCHAR(50),
        anomaly_percentage FLOAT NOT NULL,
        severity VARCHAR(20),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        normal_count INT,
        anomaly_count INT,
        report_file VARCHAR(255),
        acknowledged BOOLEAN DEFAULT FALSE,
        notes TEXT
    );
    
    CREATE TABLE IF NOT EXISTS system_metrics (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        captures_total INT DEFAULT 0,
        processed_total INT DEFAULT 0,
        predictions_total INT DEFAULT 0,
        alerts_total INT DEFAULT 0,
        capture_queue_size INT DEFAULT 0,
        processing_queue_size INT DEFAULT 0,
        prediction_queue_size INT DEFAULT 0,
        processing_time_avg FLOAT
    );
    
    CREATE TABLE IF NOT EXISTS traffic_statistics (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        total_flows INT,
        normal_flows INT,
        anomalous_flows INT,
        top_source_ip VARCHAR(50),
        top_destination_ip VARCHAR(50),
        top_protocol VARCHAR(20),
        avg_packet_size FLOAT
    );
    
    CREATE TABLE IF NOT EXISTS attack_type_metrics (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        attack_type VARCHAR(100) NOT NULL,
        predictions_count INT DEFAULT 0,
        normal_count INT DEFAULT 0,
        anomaly_count INT DEFAULT 0,
        anomaly_percentage FLOAT
    );
    """
    
    with engine.connect() as conn:
        for statement in create_tables_sql.split(';'):
            if statement.strip():
                conn.execute(text(statement))
                conn.commit()
    
    print("✓ Database migration completed")


if __name__ == "__main__":
    # Run migration
    print("Running database migration...")
    try:
        migrate_database()
    except Exception as e:
        print(f"Migration error: {e}")
