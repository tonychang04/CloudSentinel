# CloudSentinel

CloudSentinel is an automated log analysis and threat prevention system for AWS environments. It fetches logs from CloudWatch, analyzes them for potential security threats, and can automatically take preventive actions such as blocking suspicious IP addresses.

## Features

- Automated CloudWatch log fetching and analysis
- Threat detection using pattern matching and keyword analysis
- Automated prevention actions (e.g., blocking IPs in security groups)


## Environment Setup

### Backend Environment

1. Create a virtual environment:
   ```
   python -m venv venv
   ```

2. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```
     source venv/bin/activate
     ```
     

3. Create a `.env` file in the project root directory with the following content:
   ```
   DEMO_MODE=True # Set to True to enable demo mode


   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   AWS_REGION=your_region
   
   # Optional: Enable AI-powered security analysis
   OPENAI_API_KEY=your_openai_api_key
   
   CLOUDTRAIL_LOOKBACK_HOURS=2
  
   ```

4. Install python-dotenv and other dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Start the Flask server:
   ```
   python main.py
   ```

### Frontend Environment

1. Navigate to the frontend directory:
   ```
   cd cloudsentinel-frontend
   ```

2. Install Node.js dependencies:
   ```
   npm install
   ```

3. Start the development server:
   ```
   npm start
   ```

The application should now be running with:
- Backend API server at http://localhost:5000
- Frontend development server at http://localhost:3000

### Loading Environment Variables

Make sure your application is set up to load the `.env` file. In your `main.py`, add the following at the top:

```python
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Access environment variables
aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_region = os.getenv('AWS_REGION')
openai_api_key = os.getenv('OPENAI_API_KEY')
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
