// main.cpp
// Simple password checker in C++: weak-list lookup, scoring, Shannon & pool entropy
#include <bits/stdc++.h>
using namespace std;

const string WEAK_FILE = "weak_passwords.txt";

unordered_set<string> load_weak(const string& path = WEAK_FILE) {
    unordered_set<string> s;
    ifstream f(path);
    string line;
    while (getline(f, line)) {
        if (!line.empty()) s.insert(line);
    }
    return s;
}

bool has_upper(const string& s){ for(char c: s) if (isupper((unsigned char)c)) return true; return false; }
bool has_lower(const string& s){ for(char c: s) if (islower((unsigned char)c)) return true; return false; }
bool has_digit(const string& s){ for(char c: s) if (isdigit((unsigned char)c)) return true; return false; }
bool has_symbol(const string& s){ for(char c: s) if (!isalnum((unsigned char)c)) return true; return false; }

double shannon_entropy(const string& s){
    if (s.empty()) return 0.0;
    unordered_map<char,int> cnt;
    for(char c: s) cnt[c]++;
    double H = 0.0;
    double n = (double)s.size();
    for(auto &p: cnt){
        double prob = p.second / n;
        H -= prob * log2(prob);
    }
    return H * n; // total bits
}

double pool_entropy(const string& s){
    int pool = 0;
    if (has_lower(s)) pool += 26;
    if (has_upper(s)) pool += 26;
    if (has_digit(s)) pool += 10;
    if (has_symbol(s)) pool += 32;
    if (pool == 0) return 0.0;
    double bits_per_char = log2((double)pool);
    return bits_per_char * s.size();
}

string classify_entropy(double bits){
    if (bits < 28) return "Very weak";
    if (bits < 36) return "Weak";
    if (bits < 60) return "Moderate";
    if (bits < 128) return "Strong";
    return "Very strong";
}

int score_password(const string& s, const unordered_set<string>& weak){
    if (weak.find(s) != weak.end()) return 0;
    int score = 0;
    if (s.size() >= 8) score += 2;
    if (has_upper(s)) score += 1;
    if (has_lower(s)) score += 1;
    if (has_digit(s)) score += 1;
    if (has_symbol(s)) score += 1;
    return score;
}

int main(){
    auto weak = load_weak();
    cout << "Password to check: ";
    string pwd;
    getline(cin, pwd);
    int score = score_password(pwd, weak);
    double ent_sh = shannon_entropy(pwd);
    double ent_pool = pool_entropy(pwd);
    double ent = max(ent_sh, ent_pool);
    string label = (weak.find(pwd) != weak.end()) ? "Very weak (common password)" : classify_entropy(ent);

    cout << "Score: " << score << "  Label: " << label << "\n";
    cout << fixed << setprecision(2);
    cout << "Entropy (shannon): " << ent_sh << " bits\n";
    cout << "Entropy (pool):    " << ent_pool << " bits\n";
    if (weak.find(pwd) != weak.end()) {
        cout << "-> REJECT: password in weak list\n";
        return 0;
    }
    cout << "Advice:\n";
    if (pwd.size() < 12) cout << "- Use a longer passphrase (>=12 chars) or 3+ random words.\n";
    if (!has_symbol(pwd)) cout << "- Add symbols or punctuation.\n";
    if (!(has_upper(pwd) && has_lower(pwd))) cout << "- Mix upper and lower case.\n";
    if (!has_digit(pwd)) cout << "- Add numbers.\n";
    return 0;
}
