
    # Calculate score
    score = sum(criteria.values())
    max_score = len(criteria)
    percentage = (score / max_score) * 100
    
    # Determine strength level
    if percentage >= 87.5:
        strength = "Very Strong"
        color = "green"
    elif percentage >= 75:
        strength = "Strong"
        color = "lightgreen"
    elif percentage >= 62.5:
        strength = "Moderate"
        color = "orange"
    elif percentage >= 50:
        strength = "Weak"
        color = "red"
    else:
        strength = "Very Weak"
        color = "darkred"
    
    return {
        'criteria': criteria,
        'score': score,
        'max_score': max_score,
        'percentage': percentage,
        'strength': strength,
        'color': color
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

def main():
    st.set_page_config(
        page_title="Password Strength Checker",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Password Strength Checker")
    st.markdown("---")
    
    # Sidebar with information
    with st.sidebar:
        st.header("📋 Security Tips")
        st.markdown("""
        **Strong passwords should have:**
        - At least 8 characters (12+ recommended)
        - Mix of uppercase and lowercase
        - Numbers and special characters
        - No common patterns or words
        - No repeated characters
        
        **Additional Tips:**
        - Use a unique password for each account
        - Consider using a password manager
        - Enable two-factor authentication
        - Update passwords regularly
        """)
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Enter Password to Check")
        
        # Password input with toggle for visibility
        show_password = st.checkbox("Show password", value=False)
        password_type = "text" if show_password else "password"
        
        password = st.text_input(
            "Password:",
            type=password_type,
            help="Enter your password to check its strength"
        )
        
        if password:
            # Analyze password
            analysis = check_password_strength(password)
            
            # Display strength meter
            st.subheader("🎯 Strength Analysis")
            
            # Progress bar
            progress_color = analysis['color']
            st.markdown(f"""
            <div style="background-color: #f0f0f0; border-radius: 10px; padding: 10px; margin: 10px 0;">
                <div style="background-color: {progress_color}; height: 30px; border-radius: 5px; width: {analysis['percentage']}%; display: flex; align-items: center; justify-content: center;">
                    <span style="color: white; font-weight: bold;">{analysis['strength']}</span>
                </div>
                <p style="text-align: center; margin: 5px 0; font-weight: bold;">
                    Score: {analysis['score']}/{analysis['max_score']} ({analysis['percentage']:.1f}%)
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Detailed criteria breakdown
            st.subheader("📊 Detailed Analysis")
            
            criteria_labels = {
                'length': 'Minimum Length (8+ chars)',
                'uppercase': 'Uppercase Letters',
                'lowercase': 'Lowercase Letters',
                'digits': 'Numbers',
                'special_chars': 'Special Characters',
                'no_common_patterns': 'No Common Patterns',
                'no_repeated_chars': 'No Repeated Characters',
                'good_length': 'Good Length (12+ chars)'
            }
            
            for key, value in analysis['criteria'].items():
                icon = "✅" if value else "❌"
                st.write(f"{icon} {criteria_labels[key]}")
            
            # Suggestions for improvement
            suggestions = generate_suggestions(analysis['criteria'])
            if suggestions:
                st.subheader("💡 Suggestions for Improvement")
                for suggestion in suggestions:
                    st.write(suggestion)
            else:
                st.success("🎉 Excellent! Your password meets all security criteria.")
    
    with col2:
        if password:
            # Password statistics
            st.subheader("📈 Password Stats")
            
            stats_container = st.container()
            with stats_container:
                st.metric("Length", len(password))
                st.metric("Unique Characters", len(set(password)))
                st.metric("Uppercase Count", sum(1 for c in password if c.isupper()))
                st.metric("Lowercase Count", sum(1 for c in password if c.islower()))
                st.metric("Digit Count", sum(1 for c in password if c.isdigit()))
                st.metric("Special Char Count", sum(1 for c in password if c in string.punctuation))
            
            # Character composition chart
            st.subheader("🔤 Character Types")
            
            char_types = {
                'Uppercase': sum(1 for c in password if c.isupper()),
                'Lowercase': sum(1 for c in password if c.islower()),
                'Digits': sum(1 for c in password if c.isdigit()),
                'Special': sum(1 for c in password if c in string.punctuation),
                'Spaces': sum(1 for c in password if c.isspace())
            }
            
            # Filter out zero counts
            char_types = {k: v for k, v in char_types.items() if v > 0}
            
            if char_types:
                st.bar_chart(char_types)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "⚠️ **Security Note**: This tool runs locally in your browser. "
        "Your password is not sent to any server or stored anywhere."
    )

if __name__ == "__main__":
    main()

