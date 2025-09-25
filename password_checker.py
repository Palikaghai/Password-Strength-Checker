
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











