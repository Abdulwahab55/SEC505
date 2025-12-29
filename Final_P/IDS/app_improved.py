"""
Improved Flask Application with Database Integration
"""

from flask import Flask, redirect, render_template, request, session, url_for, jsonify
from datetime import datetime, timedelta
from models import db, Users, Alert, SystemMetrics, TrafficStatistics, AttackTypeMetrics

app = Flask(__name__)
app.secret_key = "any key"  # TODO: Change this to environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost:3306/projDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Create tables if they don't exist
with app.app_context():
    db.create_all()


@app.route('/', methods=['GET', 'POST'])
def index():
    """Main dashboard showing latest alerts"""
    if session.get('sessionName') is None:
        return redirect('login')
    
    # Get latest critical alert
    latest_alert = Alert.query.filter(
        Alert.anomaly_percentage >= 40
    ).order_by(Alert.timestamp.desc()).first()
    
    # Get recent alerts count
    recent_alerts_count = Alert.query.filter(
        Alert.timestamp >= datetime.utcnow() - timedelta(hours=24),
        Alert.acknowledged == False
    ).count()
    
    return render_template('index.html', 
                          latest_alert=latest_alert,
                          recent_alerts_count=recent_alerts_count)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # TODO: Hash this password
        email = request.form['email']
        
        # Check if email already exists
        existing_user = Users.query.filter_by(email=email).first()
        if existing_user:
            session['error'] = "Email already exists!"
            return redirect('register')
        
        new_user = Users(username=username, password=password, email=email)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect('/')
        except Exception as e:
            session['error'] = f"Registration failed: {str(e)}"
            return redirect('register')
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = Users.query.filter_by(email=email).first()
        
        if user and user.password == password:  # TODO: Use password hashing
            session['sessionName'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            session['msg'] = "Invalid email or password!"
            return redirect('login')
    
    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """Real-time dashboard with all attack visualizations"""
    if session.get('sessionName') is None:
        return redirect('login')
    
    # Get latest metrics
    latest_metrics = SystemMetrics.query.order_by(
        SystemMetrics.timestamp.desc()
    ).first()
    
    # Get attack type statistics (last hour)
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    attack_stats = AttackTypeMetrics.query.filter(
        AttackTypeMetrics.timestamp >= one_hour_ago
    ).all()
    
    return render_template('dashboard.html',
                          metrics=latest_metrics,
                          attack_stats=attack_stats)


@app.route('/alerts', methods=['GET'])
def alerts_page():
    """View all alerts with filtering and pagination"""
    if session.get('sessionName') is None:
        return redirect('login')
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Filter options
    severity = request.args.get('severity', None)
    acknowledged = request.args.get('acknowledged', None)
    attack_type = request.args.get('attack_type', None)
    
    query = Alert.query
    
    if severity:
        # Note: severity is calculated property, so we filter by percentage
        if severity == 'Critical':
            query = query.filter(Alert.anomaly_percentage >= 75)
        elif severity == 'High':
            query = query.filter(Alert.anomaly_percentage >= 50, Alert.anomaly_percentage < 75)
        elif severity == 'Medium':
            query = query.filter(Alert.anomaly_percentage >= 25, Alert.anomaly_percentage < 50)
        elif severity == 'Low':
            query = query.filter(Alert.anomaly_percentage < 25)
    
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == (acknowledged == 'true'))
    
    if attack_type:
        query = query.filter(Alert.attack_type == attack_type)
    
    alerts_pagination = query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get unique attack types for filter
    attack_types = db.session.query(Alert.attack_type).distinct().all()
    attack_types = [at[0] for at in attack_types]
    
    return render_template('alerts.html',
                          alerts=alerts_pagination.items,
                          pagination=alerts_pagination,
                          attack_types=attack_types)


@app.route('/alert/<int:alert_id>', methods=['GET', 'POST'])
def alert_detail(alert_id):
    """View detailed information about a specific alert"""
    if session.get('sessionName') is None:
        return redirect('login')
    
    alert = Alert.query.get_or_404(alert_id)
    
    if request.method == 'POST':
        # Update alert (acknowledge, add notes)
        if 'acknowledge' in request.form:
            alert.acknowledged = True
        if 'notes' in request.form:
            alert.notes = request.form['notes']
        
        db.session.commit()
        return redirect(url_for('alert_detail', alert_id=alert_id))
    
    return render_template('alert_detail.html', alert=alert)


@app.route('/statistics', methods=['GET'])
def statistics():
    """View historical statistics and trends"""
    if session.get('sessionName') is None:
        return redirect('login')
    
    # Get time range
    hours = request.args.get('hours', 24, type=int)
    time_ago = datetime.utcnow() - timedelta(hours=hours)
    
    # Get metrics over time
    metrics_history = SystemMetrics.query.filter(
        SystemMetrics.timestamp >= time_ago
    ).order_by(SystemMetrics.timestamp.asc()).all()
    
    # Get traffic statistics
    traffic_stats = TrafficStatistics.query.filter(
        TrafficStatistics.timestamp >= time_ago
    ).order_by(TrafficStatistics.timestamp.asc()).all()
    
    # Get alert counts by type
    alert_counts = db.session.query(
        Alert.attack_type,
        db.func.count(Alert.id).label('count')
    ).filter(Alert.timestamp >= time_ago).group_by(Alert.attack_type).all()
    
    return render_template('statistics.html',
                          metrics_history=metrics_history,
                          traffic_stats=traffic_stats,
                          alert_counts=alert_counts,
                          hours=hours)


@app.route('/api/alerts/recent', methods=['GET'])
def api_recent_alerts():
    """API endpoint for recent alerts (for AJAX updates)"""
    minutes = request.args.get('minutes', 5, type=int)
    time_ago = datetime.utcnow() - timedelta(minutes=minutes)
    
    alerts = Alert.query.filter(
        Alert.timestamp >= time_ago
    ).order_by(Alert.timestamp.desc()).all()
    
    return jsonify([{
        'id': a.id,
        'attack_type': a.attack_type,
        'source_ip': a.source_ip,
        'anomaly_percentage': a.anomaly_percentage,
        'severity': a.severity_level,
        'timestamp': a.timestamp.isoformat(),
        'acknowledged': a.acknowledged
    } for a in alerts])


@app.route('/api/metrics/current', methods=['GET'])
def api_current_metrics():
    """API endpoint for current system metrics"""
    metrics = SystemMetrics.query.order_by(
        SystemMetrics.timestamp.desc()
    ).first()
    
    if metrics:
        return jsonify({
            'captures_total': metrics.captures_total,
            'processed_total': metrics.processed_total,
            'predictions_total': metrics.predictions_total,
            'alerts_total': metrics.alerts_total,
            'capture_queue_size': metrics.capture_queue_size,
            'processing_queue_size': metrics.processing_queue_size,
            'prediction_queue_size': metrics.prediction_queue_size,
            'timestamp': metrics.timestamp.isoformat()
        })
    
    return jsonify({'error': 'No metrics available'}), 404


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """User logout"""
    session.clear()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # TODO: Set debug=False in production
