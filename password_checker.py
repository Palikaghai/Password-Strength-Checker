            
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















