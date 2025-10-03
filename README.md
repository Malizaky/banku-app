# ConnectApp - Cross-Platform Provider-Consumer Connection Platform

A comprehensive Flask-based web application that connects providers and consumers across multiple industries, facilitating successful deals and partnerships.

## Features

### 🎯 Core Functionality
- **Multi-Role Support**: Users can be Skillers, Producers, Consultants, Thinkers, Investors, Distributors, and Consumers
- **Centralized Banks**: Organized repositories for Products, Services, Knowledge, Ideas, and Needs
- **Smart Matching**: AI-powered recommendations and matching system
- **Deal Management**: Complete deal flow from initiation to completion
- **Earning Opportunities**: Multiple ways to earn through referrals, projects, and services
- **Review System**: Comprehensive rating and review system for trust building

### 👥 User Types

#### Internal Staff (Platform Management)
- **Admin**: Full system control, user management, analytics
- **Connector**: Matches providers with consumers, facilitates deals
- **Collector**: Collects market data, adds users/products/services
- **Verifier**: Verifies accounts, products, services, quality compliance

#### External Users (Clients)
- **Skiller**: Service providers (consultants, trainers, artists)
- **Producer**: Product creators (physical/digital)
- **Consultant**: Knowledge and expertise providers
- **Thinker**: Idea generators
- **Investor**: Funding providers
- **Distributor**: Logistics and distribution
- **Consumer**: All users are also consumers

### 🏦 Centralized Banks
- **Bank of Products**: Physical and digital products
- **Bank of Services**: Professional services and expertise
- **Bank of Knowledge**: Educational content and consultation
- **Bank of Ideas**: Innovative concepts and projects
- **Bank of Needs**: User requests and requirements

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy (SQLite/PostgreSQL)
- **Frontend**: Bootstrap 5, HTML5, CSS3, JavaScript
- **Real-time**: Socket.IO
- **Authentication**: Flask-Login
- **Forms**: Flask-WTF
- **Payments**: Stripe integration ready

## Installation & Setup

### Prerequisites
- Python 3.8+
- pip (Python package installer)

### 1. Clone the Repository
```bash
git clone <repository-url>
cd connectapp
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Environment Configuration
Create a `.env` file in the root directory:
```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///app.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### 5. Initialize Database
```bash
python init_db.py
```

This will create:
- Database tables
- Default roles (Admin, Connector, Collector, Verifier)
- Default user tags (Skiller, Producer, Consultant, etc.)
- Default banks (Products, Services, Knowledge, Ideas, Needs)
- Admin user (email: admin@connectapp.com, password: admin123)

### 6. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

### Getting Started
1. **Register**: Create a new account and select your roles
2. **Create Profiles**: Set up personal, company, team, or project profiles
3. **Add Items**: List your products, services, knowledge, or ideas
4. **Browse Banks**: Discover opportunities in our centralized banks
5. **Create Deals**: Connect with other users and manage transactions
6. **Earn Money**: Get paid for referrals, project contributions, and services

### Admin Panel
Access the admin panel at `/admin` with admin credentials to:
- Manage users and roles
- Monitor deals and transactions
- Verify items and services
- View analytics and reports

## Project Structure

```
connectapp/
├── app.py                 # Main Flask application
├── models.py              # Database models
├── init_db.py            # Database initialization script
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables
├── routes/               # Blueprint routes
│   ├── auth.py          # Authentication routes
│   ├── dashboard.py     # Dashboard routes
│   ├── banks.py         # Banks management
│   ├── deals.py         # Deal management
│   ├── profiles.py      # Profile management
│   └── admin.py         # Admin panel
├── templates/            # HTML templates
│   ├── base.html        # Base template
│   ├── index.html       # Homepage
│   ├── about.html       # About page
│   ├── auth/            # Authentication templates
│   ├── dashboard/       # Dashboard templates
│   ├── banks/           # Banks templates
│   ├── deals/           # Deals templates
│   ├── profiles/        # Profile templates
│   └── admin/           # Admin templates
└── static/              # Static assets
    ├── css/
    │   └── style.css    # Custom styles
    └── js/
        └── main.js      # JavaScript functionality
```

## API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `GET /auth/logout` - User logout

### Dashboard
- `GET /dashboard/` - Main dashboard
- `GET /dashboard/stats` - User statistics
- `GET /dashboard/notifications` - User notifications

### Banks
- `GET /banks/` - List all banks
- `GET /banks/<bank_type>` - Get bank items
- `GET /banks/item/<item_id>` - Item details
- `GET /banks/search` - Search items

### Deals
- `GET /deals/` - List user deals
- `POST /deals/create` - Create new deal
- `GET /deals/<deal_id>` - Deal details
- `POST /deals/<deal_id>/update-status` - Update deal status

### Profiles
- `GET /profiles/` - User profiles
- `POST /profiles/create` - Create profile
- `GET /profiles/<profile_id>` - Profile details
- `POST /profiles/<profile_id>/items/create` - Create item

### Admin
- `GET /admin/` - Admin dashboard
- `GET /admin/users` - User management
- `GET /admin/roles` - Role management
- `GET /admin/deals` - Deal management
- `GET /admin/verifications` - Item verification

## Database Schema

### Core Tables
- **users**: User accounts and authentication
- **roles**: System roles and permissions
- **tags**: User tags and categories
- **profiles**: User profiles and entities
- **items**: Products, services, knowledge, ideas
- **deals**: Transactions and agreements
- **reviews**: Ratings and feedback
- **earnings**: User earnings and payments
- **notifications**: System notifications

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please contact the development team or create an issue in the repository.

## Roadmap

### Phase 1 (Current)
- ✅ Basic user authentication and roles
- ✅ Profile and item management
- ✅ Deal creation and management
- ✅ Admin panel functionality

### Phase 2 (Planned)
- 🔄 Real-time messaging and notifications
- 🔄 Payment integration (Stripe)
- 🔄 Mobile app (React Native)
- 🔄 Advanced search and filtering

### Phase 3 (Future)
- 📋 AI-powered matching algorithms
- 📋 Advanced analytics and reporting
- 📋 API for third-party integrations
- 📋 Multi-language support

---

**BankU** - Your comprehensive banking and financial services platform! 🏦

