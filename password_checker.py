d
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






