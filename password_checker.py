import streamlit as st
import re
import math
import hashlib
from typing import Dict, List, Tuple, Optional
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# Common password blacklist (in a real app, this would be loaded from a file or API)
COMMON_PASSWORDS = {
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
    'admin','1234567890', 'password1',
    'qwerty123', 'dragon', 'master', 'hello', 'freedom', 'whatever',
    'qazwsx', 'trustno1', '654321', 'jordan23', 'harley', 'password1',
    '1234', 'robert', 'matthew', 'jordan', 'asshole', 'daniel', 'andrew',
    'joshua', 'michael', 'charlie', 'michelle', 'jessica', 'david',
    'ashley', 'jennifer', 'james', 'samantha', 'william', 'sarah',
    'christopher', 'jessica', 'matthew', 'daniel', 'andrew', 'joshua',
    'michael', 'charlie', 'michelle', 'jessica', 'david', 'ashley',
    'jennifer', 'james', 'samantha', 'william', 'sarah', 'christopher'
}

# Keyboard patterns for detection
KEYBOARD_PATTERNS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qwerty', 'asdf', 'zxcv',
    '1234567890', '0987654321', 'qwerty123', 'asdf1234', 'zxcv1234',
    'qweasdzxc', 'qazwsxedc', 'rfvtgbyhn', 'tgbyhnujm', 'yhnujmik',
    'ujmikolp', 'ikolp', 'olp', 'qwertyuiopasdfghjklzxcvbnm'
]

def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(password)
    password_length = len(password)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / password_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_character_set_entropy(password: str) -> float:
    """Calculate entropy based on character set diversity."""
    char_sets = {
        'lowercase': bool(re.search(r'[a-z]', password)),
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'digits': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'extended': bool(re.search(r'[^\x00-\x7F]', password))  # Unicode characters
    }
    
    # Calculate possible character set size
    charset_size = 0
    if char_sets['lowercase']:
        charset_size += 26
    if char_sets['uppercase']:
        charset_size += 26
    if char_sets['digits']:
        charset_size += 10
    if char_sets['special']:
        charset_size += 32  # Common special characters
    if char_sets['extended']:
        charset_size += 1000  # Approximate for Unicode
    
    if charset_size == 0:
        return 0.0
    
    # Entropy = log2(charset_size^length)
    return len(password) * math.log2(charset_size)

def detect_keyboard_walks(password: str) -> List[str]:
    """Detect keyboard walk patterns in password."""
    password_lower = password.lower()
    detected_patterns = []
    
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            detected_patterns.append(pattern)
        # Check reverse patterns
        if pattern[::-1] in password_lower:
            detected_patterns.append(f"{pattern} (reversed)")
    
    return detected_patterns

def detect_character_substitutions(password: str) -> List[str]:
    """Detect common character substitutions like leetspeak."""
    substitutions = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['7'],
        'l': ['1'],
        'g': ['9'],
        'b': ['6'],
        'z': ['2']
    }
    
    detected_subs = []
    password_lower = password.lower()
    
    for char, subs in substitutions.items():
        for sub in subs:
            if sub in password:
                # Check if it's likely a substitution
                if char in password_lower:
                    detected_subs.append(f"'{sub}' might be substitution for '{char}'")
    
    return detected_subs

def check_blacklist(password: str) -> bool:
    """Check if password is in common password blacklist."""
    return password.lower() in COMMON_PASSWORDS

def check_user_specific_info(password: str, username: str = "", email: str = "", birthdate: str = "") -> List[str]:
    """Check for user-specific information in password."""
    warnings = []
    password_lower = password.lower()
    
    if username and username.lower() in password_lower:
        warnings.append("Password contains username")
    
    if email:
        email_local = email.split('@')[0].lower()
        if email_local in password_lower:
            warnings.append("Password contains email username")
    
    if birthdate:
        # Check for year
        year = birthdate.split('-')[0] if '-' in birthdate else birthdate[-4:]
        if year in password:
            warnings.append("Password contains birth year")
        
        # Check for date patterns
        date_parts = re.findall(r'\d{1,2}', birthdate)
        for part in date_parts:
            if part in password:
                warnings.append("Password contains birth date")
    
    return warnings

def check_password_strength(password: str, username: str = "", email: str = "", birthdate: str = "") -> Dict:
    # Basic criteria
    criteria = {
        'length': len(password) >= 8,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'digits': bool(re.search(r'\d', password)),
        'special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'no_common_patterns': not check_common_patterns(password),
        'no_repeated_chars': not has_repeated_chars(password),
        'good_length': len(password) >= 12,
        'not_blacklisted': not check_blacklist(password),
        'no_keyboard_walks': len(detect_keyboard_walks(password)) == 0,
        'no_character_substitutions': len(detect_character_substitutions(password)) == 0,
        'no_user_info': len(check_user_specific_info(password, username, email, birthdate)) == 0
    }
    
    # Advanced analysis
    entropy = calculate_entropy(password)
    charset_entropy = calculate_character_set_entropy(password)
    keyboard_walks = detect_keyboard_walks(password)
    substitutions = detect_character_substitutions(password)
    user_warnings = check_user_specific_info(password, username, email, birthdate)
    
    # Calculate score with weighted criteria
    weights = {
        'length': 1, 'uppercase': 1, 'lowercase': 1, 'digits': 1,
        'special_chars': 2, 'no_common_patterns': 2, 'no_repeated_chars': 1,
        'good_length': 2, 'not_blacklisted': 3, 'no_keyboard_walks': 2,
        'no_character_substitutions': 1, 'no_user_info': 2
    }
    
    weighted_score = sum(weights[key] * (1 if criteria[key] else 0) for key in weights)
    max_weighted_score = sum(weights.values())
    percentage = (weighted_score / max_weighted_score) * 100
    
    # Entropy-based strength adjustment
    if entropy >= 4.0:
        percentage += 5
    elif entropy < 2.0:
        percentage -= 10
    
    if charset_entropy >= 50:
        percentage += 5
    elif charset_entropy < 20:
        percentage -= 10
    
    percentage = max(0, min(100, percentage))
    
    # Determine strength level
    if percentage >= 90:
        strength = "Very Strong"
        color = "darkgreen"
    elif percentage >= 75:
        strength = "Strong"
        color = "green"
    elif percentage >= 60:
        strength = "Moderate"
        color = "yellow"
    elif percentage >= 40:
        strength = "Weak"
        color = "orange"
    else:
        strength = "Very Weak"
        color = "red"
    
    return {
        'criteria': criteria,
        'score': weighted_score,
        'max_score': max_weighted_score,
        'percentage': percentage,
        'strength': strength,
        'color': color,
        'entropy': entropy,
        'charset_entropy': charset_entropy,
        'keyboard_walks': keyboard_walks,
        'substitutions': substitutions,
        'user_warnings': user_warnings,
        'is_blacklisted': check_blacklist(password)
    }

def check_common_patterns(password: str) -> bool:
    """Check for common weak patterns in password."""
    password_lower = password.lower()
    
    # Common patterns
    common_patterns = [
        r'123',
        r'abc',
        r'qwerty',
        r'password',
        r'admin',
        r'login',
        r'user'
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password_lower):
            return True
    
    return False

def has_repeated_chars(password: str, threshold: int = 3) -> bool:
    """Check if password has too many repeated characters."""
    for char in set(password):
        if password.count(char) >= threshold:
            return True
    return False

def generate_suggestions(criteria: Dict) -> List[str]:
    """Generate improvement suggestions based on failed criteria."""
    suggestions = []
    
    if not criteria['length']:
        suggestions.append("🔹 Use at least 8 characters (12+ recommended)")
    
    if not criteria['uppercase']:
        suggestions.append("🔹 Include at least one uppercase letter (A-Z)")
    
    if not criteria['lowercase']:
        suggestions.append("🔹 Include at least one lowercase letter (a-z)")
    
    if not criteria['digits']:
        suggestions.append("🔹 Include at least one number (0-9)")
    
    if not criteria['special_chars']:
        suggestions.append("🔹 Include special characters (!@#$%^&*)")
    
    if not criteria['no_common_patterns']:
        suggestions.append("🔹 Avoid common patterns like '123', 'abc', 'qwerty'")
    
    if not criteria['no_repeated_chars']:
        suggestions.append("🔹 Avoid repeating the same character 3+ times")
    
    if not criteria['good_length']:
        suggestions.append("🔹 Consider using 12+ characters for better security")
    
    return suggestions

def generate_secure_password(length: int = 16, include_symbols: bool = True, 
                           include_uppercase: bool = True, include_lowercase: bool = True,
                           include_digits: bool = True, exclude_similar: bool = True) -> str:
    """Generate a cryptographically secure password."""
    charset = ""
    
    if include_lowercase:
        charset += string.ascii_lowercase
    if include_uppercase:
        charset += string.ascii_uppercase
    if include_digits:
        charset += string.digits
    if include_symbols:
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if exclude_similar:
        # Remove similar characters
        charset = charset.replace('0', '').replace('O', '').replace('o', '')
        charset = charset.replace('1', '').replace('l', '').replace('I', '')
        charset = charset.replace('5', '').replace('S', '').replace('s', '')
    
    if not charset:
        charset = string.ascii_letters + string.digits
    
    return ''.join(secrets.choice(charset) for _ in range(length))

def check_breach_status(password: str) -> Dict:
    """Check if password has been compromised in data breaches using HaveIBeenPwned API."""
    try:
        # Hash the password with SHA-1
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        hash_prefix = password_hash[:5]
        hash_suffix = password_hash[5:]
        
        # Make request to HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Check if our hash suffix is in the response
            for line in response.text.splitlines():
                if line.startswith(hash_suffix):
                    count = int(line.split(':')[1])
                    return {
                        'breached': True,
                        'count': count,
                        'message': f"Password found in {count} data breaches"
                    }
            
            return {
                'breached': False,
                'count': 0,
                'message': "Password not found in known breaches"
            }
        else:
            return {
                'breached': None,
                'count': 0,
                'message': "Unable to check breach status"
            }
    except Exception as e:
        return {
            'breached': None,
            'count': 0,
            'message': f"Error checking breach status: {str(e)}"
        }

def get_context_requirements(context: str) -> Dict:
    """Get password requirements based on context (banking, healthcare, enterprise, etc.)."""
    requirements = {
        'general': {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_symbols': False,
            'max_age_days': 90,
            'prevent_reuse': 5
        },
        'banking': {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_symbols': True,
            'max_age_days': 60,
            'prevent_reuse': 10
        },
        'healthcare': {
            'min_length': 10,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_symbols': True,
            'max_age_days': 45,
            'prevent_reuse': 8
        },
        'enterprise': {
            'min_length': 14,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_symbols': True,
            'max_age_days': 30,
            'prevent_reuse': 12
        },
        'government': {
            'min_length': 16,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_symbols': True,
            'max_age_days': 30,
            'prevent_reuse': 15
        }
    }
    
    return requirements.get(context, requirements['general'])

def get_theme_colors(is_dark_mode: bool) -> Dict[str, str]:
    """Get color scheme based on theme mode."""
    if is_dark_mode:
        return {
            'background': '#0e1117',
            'secondary_background': '#262730',
            'text': '#fafafa',
            'primary': '#ff6b6b',
            'secondary': '#4ecdc4',
            'success': '#45b7d1',
            'warning': '#f9ca24',
            'error': '#f0932b',
            'info': '#6c5ce7',
            'chart_colors': ['#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#f0932b', '#6c5ce7', '#a55eea', '#26de81']
        }
    else:
        return {
            'background': '#ffffff',
            'secondary_background': '#f8f9fa',
            'text': '#262730',
            'primary': '#ff6b6b',
            'secondary': '#4ecdc4',
            'success': '#00b894',
            'warning': '#fdcb6e',
            'error': '#e17055',
            'info': '#74b9ff',
            'chart_colors': ['#ff6b6b', '#4ecdc4', '#00b894', '#fdcb6e', '#e17055', '#74b9ff', '#a29bfe', '#fd79a8']
        }

def create_multicolor_chart(data: Dict, title: str, chart_type: str = 'bar', is_dark_mode: bool = False) -> go.Figure:
    """Create multicolor charts using Plotly."""
    colors = get_theme_colors(is_dark_mode)['chart_colors']
    
    if chart_type == 'bar':
        fig = go.Figure(data=[
            go.Bar(
                x=list(data.keys()),
                y=list(data.values()),
                marker=dict(
                    color=colors[:len(data)],
                    line=dict(width=2, color='white' if is_dark_mode else 'black')
                ),
                text=list(data.values()),
                textposition='auto',
            )
        ])
    elif chart_type == 'pie':
        fig = go.Figure(data=[
            go.Pie(
                labels=list(data.keys()),
                values=list(data.values()),
                marker=dict(colors=colors[:len(data)]),
                textinfo='label+percent',
                textfont=dict(color='white' if is_dark_mode else 'black')
            )
        ])
    
    # Update layout
    theme_colors = get_theme_colors(is_dark_mode)
    fig.update_layout(
        title=dict(
            text=title,
            font=dict(color=theme_colors['text'], size=16)
        ),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color=theme_colors['text']),
        xaxis=dict(
            gridcolor=theme_colors['secondary_background'],
            color=theme_colors['text']
        ),
        yaxis=dict(
            gridcolor=theme_colors['secondary_background'],
            color=theme_colors['text']
        ),
        showlegend=False
    )
    
    return fig

def apply_theme_styles(is_dark_mode: bool):
    """Apply theme-specific CSS styles."""
    theme_colors = get_theme_colors(is_dark_mode)
    
    css = f"""
    <style>
    .stApp {{
        background-color: {theme_colors['background']};
        color: {theme_colors['text']};
    }}
    
    .main .block-container {{
        background-color: {theme_colors['background']};
        color: {theme_colors['text']};
    }}
    
    .stSidebar {{
        background-color: {theme_colors['secondary_background']};
    }}
    
    .stSelectbox > div > div {{
        background-color: {theme_colors['secondary_background']};
        color: {theme_colors['text']};
    }}
    
    .stTextInput > div > div > input {{
        background-color: {theme_colors['secondary_background']};
        color: {theme_colors['text']};
        border-color: {theme_colors['primary']};
    }}
    
    .stButton > button {{
        background-color: {theme_colors['primary']};
        color: white;
        border: none;
        border-radius: 5px;
    }}
    
    .stButton > button:hover {{
        background-color: {theme_colors['secondary']};
    }}
    
    .stMetric {{
        background-color: {theme_colors['secondary_background']};
        border-radius: 10px;
        padding: 10px;
        border: 1px solid {theme_colors['primary']};
    }}
    
    .stSuccess {{
        background-color: {theme_colors['success']}20;
        border: 1px solid {theme_colors['success']};
        color: {theme_colors['success']};
    }}
    
    .stWarning {{
        background-color: {theme_colors['warning']}20;
        border: 1px solid {theme_colors['warning']};
        color: {theme_colors['warning']};
    }}
    
    .stError {{
        background-color: {theme_colors['error']}20;
        border: 1px solid {theme_colors['error']};
        color: {theme_colors['error']};
    }}
    
    .stInfo {{
        background-color: {theme_colors['info']}20;
        border: 1px solid {theme_colors['info']};
        color: {theme_colors['info']};
    }}
    
    .theme-toggle {{
        position: fixed;
        top: 10px;
        right: 10px;
        z-index: 1000;
        background-color: {theme_colors['primary']};
        color: white;
        border: none;
        border-radius: 50%;
        width: 50px;
        height: 50px;
        font-size: 20px;
        cursor: pointer;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    }}
    
    .theme-toggle:hover {{
        background-color: {theme_colors['secondary']};
        transform: scale(1.1);
    }}
    </style>
    """
    
    st.markdown(css, unsafe_allow_html=True)

def main():
    st.set_page_config(
        page_title="Advanced Password Strength Checker",
        page_icon="🔒",
        layout="wide"
    )
    
    # Initialize session state for theme
    if 'dark_mode' not in st.session_state:
        st.session_state.dark_mode = False
    
    # Theme toggle button
    col1, col2, col3 = st.columns([1, 1, 1])
    with col3:
        if st.button("🌙" if not st.session_state.dark_mode else "☀️", key="theme_toggle", help="Toggle Dark/Light Mode"):
            st.session_state.dark_mode = not st.session_state.dark_mode
            st.rerun()
    
    # Apply theme styles
    apply_theme_styles(st.session_state.dark_mode)
    
    st.title("🔒 Advanced Password Strength Checker")
    st.markdown("---")
    
    # Sidebar with context selection and password generator
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # Context selection
        context = st.selectbox(
            "Security Context:",
            ["general", "banking", "healthcare", "enterprise", "government"],
            help="Select the security context for your password requirements"
        )
        
        context_reqs = get_context_requirements(context)
        st.info(f"**{context.title()} Requirements:**\n"
                f"• Min length: {context_reqs['min_length']}\n"
                f"• Symbols required: {context_reqs['require_symbols']}\n"
                f"• Max age: {context_reqs['max_age_days']} days")
        
        st.markdown("---")
        
        # Password Generator
        st.header("🎲 Password Generator")
        
        with st.expander("Generate Secure Password"):
            gen_length = st.slider("Length", 8, 32, 16)
            gen_uppercase = st.checkbox("Uppercase", value=True)
            gen_lowercase = st.checkbox("Lowercase", value=True)
            gen_digits = st.checkbox("Digits", value=True)
            gen_symbols = st.checkbox("Symbols", value=True)
            gen_exclude_similar = st.checkbox("Exclude similar chars", value=True)
            
            if st.button("Generate Password"):
                generated = generate_secure_password(
                    gen_length, gen_symbols, gen_uppercase, 
                    gen_lowercase, gen_digits, gen_exclude_similar
                )
                st.code(generated)
                st.success("Password generated! Copy it to use.")
        
        st.markdown("---")
        
        # Security Tips
        st.header("📋 Security Tips")
        st.markdown("""
        **Advanced Security Features:**
        - Entropy calculation for randomness
        - Keyboard walk detection
        - Character substitution analysis
        - Blacklist checking
        - Data breach verification
        - User-specific info detection
        
        **Best Practices:**
        - Use unique passwords for each account
        - Consider using a password manager
        - Enable two-factor authentication
        - Update passwords regularly
        - Avoid personal information
        """)
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 Password Analysis")
        
        # User information input (optional)
        with st.expander("Personal Information (Optional - for enhanced checking)"):
            username = st.text_input("Username:", help="Check if password contains username")
            email = st.text_input("Email:", help="Check if password contains email")
            birthdate = st.text_input("Birth Date (YYYY-MM-DD):", help="Check if password contains birth date")
        
        # Password input with toggle for visibility
        show_password = st.checkbox("Show password", value=False)
        password_type = "text" if show_password else "password"
        
        password = st.text_input(
            "Password:",
            type=password_type,
            help="Enter your password to check its strength"
        )
        
        if password:
            # Analyze password with user info
            analysis = check_password_strength(password, username, email, birthdate)
            
            # Display strength meter with enhanced styling
            st.subheader("Strength Analysis")
            
            # Enhanced progress bar with theme colors
            theme_colors = get_theme_colors(st.session_state.dark_mode)
            color_map = {
                "darkgreen": theme_colors['success'],
                "green": theme_colors['secondary'], 
                "yellow": theme_colors['warning'],
                "orange": theme_colors['error'],
                "red": theme_colors['primary']
            }
            
            progress_color = color_map.get(analysis['color'], theme_colors['info'])
            
            bg_color = theme_colors['secondary_background']
            text_color = theme_colors['text']
            
            st.markdown(f"""
            <div style="background-color: {bg_color}; border: 2px solid {progress_color}; border-radius: 10px; padding: 15px; margin: 10px 0;">
                <div style="background: linear-gradient(90deg, {progress_color} 0%, {progress_color} {analysis['percentage']}%, {bg_color} {analysis['percentage']}%, {bg_color} 100%); height: 30px; border-radius: 5px; display: flex; align-items: center; justify-content: center;">
                    <span style="color: white; font-weight: bold; text-shadow: 1px 1px 2px rgba(0,0,0,0.5);">{analysis['strength']}</span>
                </div>
                <p style="text-align: center; margin: 5px 0; font-weight: bold; color: {progress_color};">
                    Score: {analysis['score']}/{analysis['max_score']} ({analysis['percentage']:.1f}%)
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Advanced metrics
            col_entropy, col_charset = st.columns(2)
            with col_entropy:
                st.metric("Shannon Entropy", f"{analysis['entropy']:.2f}", 
                         help="Higher entropy = more random")
            with col_charset:
                st.metric("Character Set Entropy", f"{analysis['charset_entropy']:.1f}",
                         help="Entropy based on character diversity")
            
            # Detailed criteria breakdown
            st.subheader("📊 Detailed Analysis")
            
            criteria_labels = {
                'length': f'Minimum Length ({context_reqs["min_length"]}+ chars)',
                'uppercase': 'Uppercase Letters',
                'lowercase': 'Lowercase Letters', 
                'digits': 'Numbers',
                'special_chars': 'Special Characters',
                'no_common_patterns': 'No Common Patterns',
                'no_repeated_chars': 'No Repeated Characters',
                'good_length': 'Good Length (12+ chars)',
                'not_blacklisted': 'Not in Blacklist',
                'no_keyboard_walks': 'No Keyboard Walks',
                'no_character_substitutions': 'No Character Substitutions',
                'no_user_info': 'No Personal Information'
            }
            
            for key, value in analysis['criteria'].items():
                if key in criteria_labels:
                    icon = "✅" if value else "❌"
                    color = "green" if value else "red"
                    st.markdown(f"<span style='color: {color};'>{icon} {criteria_labels[key]}</span>", 
                               unsafe_allow_html=True)
            
            # Advanced pattern detection results
            if analysis['keyboard_walks']:
                st.warning(f"🚨 **Keyboard walks detected:** {', '.join(analysis['keyboard_walks'])}")
            
            if analysis['substitutions']:
                st.info(f"🔤 **Character substitutions detected:** {', '.join(analysis['substitutions'])}")
            
            if analysis['user_warnings']:
                st.error(f"⚠️ **Personal information detected:** {', '.join(analysis['user_warnings'])}")
            
            if analysis['is_blacklisted']:
                st.error("🚫 **Password is in common password blacklist!**")
            
            # Breach checking
            st.subheader("🔍 Breach Status Check")
            if st.button("Check if password was breached"):
                with st.spinner("Checking breach status..."):
                    breach_status = check_breach_status(password)
                    
                    if breach_status['breached'] is True:
                        st.error(f"🚨 {breach_status['message']}")
                    elif breach_status['breached'] is False:
                        st.success(f"✅ {breach_status['message']}")
                    else:
                        st.warning(f"⚠️ {breach_status['message']}")
            
            # Enhanced suggestions
            suggestions = generate_suggestions(analysis['criteria'])
            if suggestions:
                st.subheader("💡 Suggestions for Improvement")
                for suggestion in suggestions:
                    st.write(suggestion)
            else:
                st.success("🎉 Your password meets all security criteria!")
    
    with col2:
        if password:
            # Enhanced password statistics
            st.subheader("📈 Advanced Statistics")
            
            stats_data = {
                'Length': len(password),
                'Unique Characters': len(set(password)),
                'Uppercase': sum(1 for c in password if c.isupper()),
                'Lowercase': sum(1 for c in password if c.islower()),
                'Digits': sum(1 for c in password if c.isdigit()),
                'Special': sum(1 for c in password if c in string.punctuation),
                'Spaces': sum(1 for c in password if c.isspace())
            }
            
            for key, value in stats_data.items():
                st.metric(key, value)
            
            # Character composition chart with multicolor
            st.subheader("Character Distribution")
            
            char_types = {k: v for k, v in stats_data.items() if v > 0 and k != 'Length'}
            if char_types:
                # Create multicolor bar chart
                fig_char = create_multicolor_chart(
                    char_types, 
                    "Password Character Distribution", 
                    'bar', 
                    st.session_state.dark_mode
                )
                st.plotly_chart(fig_char, use_container_width=True)
            
            # Entropy visualization with multicolor
            st.subheader("Entropy Analysis")
            entropy_data = {
                'Shannon Entropy': analysis['entropy'],
                'Character Set Entropy': min(analysis['charset_entropy'], 100)  # Cap for visualization
            }
            
            # Create multicolor bar chart for entropy
            fig_entropy = create_multicolor_chart(
                entropy_data, 
                "Password Entropy Analysis", 
                'bar', 
                st.session_state.dark_mode
            )
            st.plotly_chart(fig_entropy, use_container_width=True)
            
            # Additional pie chart for character types
            if char_types:
                st.subheader("Character Type Breakdown")
                fig_pie = create_multicolor_chart(
                    char_types, 
                    "Character Type Distribution", 
                    'pie', 
                    st.session_state.dark_mode
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            
            # Security recommendations
            st.subheader("🛡️ Security Recommendations")
            
            if analysis['percentage'] < 60:
                st.error("**High Risk:** Password needs immediate improvement")
            elif analysis['percentage'] < 80:
                st.warning("**Medium Risk:** Consider strengthening password")
            else:
                st.success("**Low Risk:** Password is reasonably secure")
            
            # Context-specific recommendations
            if context != 'general':
                st.info(f"**{context.title()} Context:** Ensure compliance with {context} security standards")
    
    # Footer with theme colors
    st.markdown("---")
    theme_colors = get_theme_colors(st.session_state.dark_mode)
    st.markdown(f"""
    <div style='text-align: center; color: {theme_colors["text"]}; background-color: {theme_colors["secondary_background"]}; padding: 20px; border-radius: 10px; margin: 20px 0;'>
        <p>⚠️ <strong>Security Note:</strong> This tool runs locally in your browser. 
        Your password is not sent to any server or stored anywhere.</p>
        <p>🔒 <strong>Breach Check:</strong> Uses HaveIBeenPwned API (only password hash is sent)</p>
        <p>🎨 <strong>Theme:</strong> Currently in {'Dark' if st.session_state.dark_mode else 'Light'} Mode</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()




