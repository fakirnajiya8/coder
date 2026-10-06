
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX 2000


void toLowerCase(char str[]) {
    int i;

    for (i = 0; str[i] != '\0'; i++) {
        str[i] = tolower(str[i]);
    }
}


int contains(char message[], char word[]) {
    return strstr(message, word) != NULL;
}


int analyzeText(char message[]) {
    int score = 0;

    printf("\n--- TEXT ANALYSIS ---\n");

    if (contains(message, "urgent")) {
        printf("[!] Urgency detected\n");
        score += 10;
    }

    if (contains(message, "immediately")) {
        printf("[!] Pressure/urgency detected\n");
        score += 10;
    }

    if (contains(message, "password")) {
        printf("[!] Password request detected\n");
        score += 15;
    }

    if (contains(message, "otp")) {
        printf("[!] OTP request detected\n");
        score += 15;
    }

    if (contains(message, "bank details")) {
        printf("[!] Bank information request detected\n");
        score += 15;
    }

    if (contains(message, "credit card")) {
        printf("[!] Credit card information request detected\n");
        score += 15;
    }

    if (contains(message, "click here")) {
        printf("[!] Suspicious click request detected\n");
        score += 10;
    }

    if (contains(message, "verify")) {
        printf("[!] Verification request detected\n");
        score += 8;
    }

    if (contains(message, "account blocked")) {
        printf("[!] Account threat detected\n");
        score += 15;
    }

    if (contains(message, "account suspended")) {
        printf("[!] Account suspension threat detected\n");
        score += 15;
    }

    if (contains(message, "prize")) {
        printf("[!] Fake prize/reward possibility\n");
        score += 10;
    }

    if (contains(message, "winner")) {
        printf("[!] Winner/reward claim detected\n");
        score += 10;
    }

    if (contains(message, "free")) {
        printf("[!] Possible fake offer detected\n");
        score += 5;
    }

    return score;
}



int analyzeURL(char message[]) {

    int score = 0;

    printf("\n--- URL ANALYSIS ---\n");

    if (contains(message, "http://")) {
        printf("[!] HTTP link detected (not HTTPS)\n");
        score += 10;
    }

    if (contains(message, "https://")) {
        printf("[+] HTTPS link detected\n");
    }

    
    if (contains(message, "192.168.") ||
        contains(message, "10.0.") ||
        contains(message, "172.16.")) {

        printf("[!] URL may contain an IP address\n");
        score += 20;
    }

    
    if (contains(message, "login")) {
        printf("[!] Login-related URL detected\n");
        score += 5;
    }

    if (contains(message, "verify")) {
        printf("[!] Verification URL detected\n");
        score += 5;
    }

    if (contains(message, "account")) {
        printf("[!] Account-related URL detected\n");
        score += 5;
    }

    if (contains(message, "free")) {
        printf("[!] Suspicious free-offer URL detected\n");
        score += 5;
    }

    return score;
}



int analyzeSender(char sender[]) {

    int score = 0;

    printf("\n--- SENDER ANALYSIS ---\n");

    if (strlen(sender) == 0) {
        printf("[!] Sender information not provided\n");
        return 0;
    }

    if (contains(sender, "gmail.com") ||
        contains(sender, "yahoo.com") ||
        contains(sender, "outlook.com")) {

        printf("[!] Sender uses a free email provider\n");
        score += 5;
    }

    if (contains(sender, "verify")) {
        printf("[!] Suspicious sender name\n");
        score += 5;
    }

    if (contains(sender, "security")) {
        printf("[!] Security-related sender name detected\n");
        score += 3;
    }

    if (contains(sender, "admin")) {
        printf("[!] Admin-related sender name detected\n");
        score += 3;
    }

    return score;
}



void displayResult(int score) {

    printf("\n====================================\n");
    printf("          FINAL RESULT\n");
    printf("====================================\n");

    printf("Risk Score: %d / 100\n", score);

    if (score >= 70) {

        printf("\nSTATUS: PHISHING\n");

        printf("\nReasons:\n");
        printf("- Multiple suspicious indicators detected.\n");
        printf("- Do NOT click suspicious links.\n");
        printf("- Do NOT provide passwords or OTPs.\n");
        printf("- Do NOT provide bank information.\n");

    } 
    else if (score >= 40) {

        printf("\nSTATUS: SUSPICIOUS\n");

        printf("\nRecommendation:\n");
        printf("- Verify the sender.\n");
        printf("- Avoid clicking unknown links.\n");
        printf("- Do not provide sensitive information.\n");

    } 
    else {

        printf("\nSTATUS: SAFE\n");

        printf("\nNo major phishing indicators detected.\n");
        printf("Still verify important messages before taking action.\n");
    }

    printf("====================================\n");
}


int main() {

    char message[MAX];
    char sender[200];

    int textScore;
    int urlScore;
    int senderScore;
    int totalScore;

    printf("====================================\n");
    printf("       SMART PHISHING DETECTOR\n");
    printf("====================================\n");

    
    printf("\nEnter the message/email/URL:\n");

    fgets(message, MAX, stdin);

    
    message[strcspn(message, "\n")] = '\0';

    
    toLowerCase(message);

    
    printf("\nEnter sender email (optional):\n");

    fgets(sender, 200, stdin);

    sender[strcspn(sender, "\n")] = '\0';

    toLowerCase(sender);

    
    printf("\n--- PREPROCESSING ---\n");
    printf("[+] Message converted to lowercase\n");
    printf("[+] Extra newline removed\n");
    printf("[+] Message ready for analysis\n");

    
    textScore = analyzeText(message);

    urlScore = analyzeURL(message);

    senderScore = analyzeSender(sender);

    
    totalScore = textScore + urlScore + senderScore;

    if (totalScore > 100) {
        totalScore = 100;
    }

    
    displayResult(totalScore);

    return 0;
}

