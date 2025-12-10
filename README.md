Cybersecurity Audit & Compliance Quiz

 Project Overview

This is a dynamic, single-page application (SPA) designed to test and reinforce knowledge in critical areas of Cybersecurity, Networking (OSI/TCP-IP), Security Audit, and Compliance. Built with HTML, CSS, and vanilla JavaScript, the project features a modern, dark-themed UI, a time-pressure element, and detailed feedback to enhance learning.
The quiz questions are sourced from real-world topics, including Cryptography, Malware, Risk Management, Key Management, and Audit Controls, making it an excellent preparation tool for technical interviews or compliance exams.

## Key Features

  * Dark Theme UI: A sleek, professional dark color scheme utilizing CSS Flexbox for a responsive and visually appealing interface.
  * Time Pressure: Each question features a **30-second countdown timer** powered by JavaScript, which automatically submits a skipped answer if time runs out.
  * Instant Feedback & Explanation: Users receive immediate visual feedback (Green/Red styling) and a detailed explanation for every answer.
  * Party Popper Animation:A fun, celebratory confetti animation is triggered upon every correct answer.
  * Randomized Questions: The quiz pulls a set number of questions (e.g., 10) randomly from a larger database (`questions.js`) on every restart, ensuring a fresh experience.
  * Final Score & Topic Review: A summary screen shows the score, percentage, and highlights specific topics where the user needs improvement.

## Technologies Used

  * HTML5: Structure and Semantics.
  * CSS3: Styling, Flexbox Layout, and animations (e.g., timer bar).
  * JavaScript (ES6): Core application logic, DOM manipulation, timer control, and quiz state management.
  * `canvas-confetti` Library: Used for the party popper animation effect.

## Getting Started

To run this quiz locally, follow these simple steps:

1.  Clone the Repository:

    ```bash
    git clone [Your Repository URL Here]
    cd [your-project-folder]
    ```

2.  Ensure Question Data:
    Verify that you have a file named `questions.js` containing the exported `allQuestions` array.

3.  Open in Browser:
    Open the `index.html` file directly in your preferred web browser.

    *(Note: Since the project uses JavaScript modules (`type="module"`), you may need to run a simple local web server (e.g., using VS Code's "Live Server" extension or Python's `http.server`) to avoid CORS issues if you encounter them.)*

## Project Structure


.
├── index.html          # Main HTML structure and links
├── style.css           # All custom dark-theme and responsive styling
├── quiz.js             # Core JavaScript logic (timer, score, question loading)
└── questions.js        # Data file containing all quiz questions (imported by quiz.js)


## Topics Covered

This quiz targets expertise in the following domains:

  * Networking Fundamentals:OSI Model, TCP/IP Model, Network Devices (Routers, Switches), Delays ($D_{trans}$, $D_{prop}$, etc.).
  * Cryptography: Symmetric vs. Asymmetric Encryption (AES, RSA), Hashing, Salting, Key Distribution Centers (KDC).
  * PKI & Identity:Certificate Authorities (CA), X.509 Certificates, Certificate Revocation List (CRL).
  * Security & Attacks: CIA Triad, Passive vs. Active Attacks (MITM, Phishing, Replay), Malware (Rootkits, Trojans).
  * Audit & Compliance: Risk Management (Mitigation, Acceptance), Access Control (Least Privilege), Security Controls (Technical, Administrative).

## Contribution

Contributions are welcome! If you find a bug or have a suggestion for improving the code or expanding the question set, please feel free to open an issue or submit a pull request.

