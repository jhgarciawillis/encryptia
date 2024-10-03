import streamlit as st
from password_manager import PasswordManager

def main():
    st.title("Password Manager")

    password_manager = PasswordManager()

    # Sidebar for adding accounts
    st.sidebar.header("Add Accounts")
    new_account = st.sidebar.text_input("Enter account name or email")
    if st.sidebar.button("Add Account"):
        if new_account:
            if 'accounts' not in st.session_state:
                st.session_state.accounts = []
            st.session_state.accounts.append(new_account)
            st.sidebar.success(f"Added: {new_account}")

    # Display current accounts
    if 'accounts' in st.session_state and st.session_state.accounts:
        st.sidebar.header("Current Accounts")
        for account in st.session_state.accounts:
            st.sidebar.text(account)

    # Main area
    option = st.radio("Choose an option:", ("Generate New Passwords", "Access Existing Passwords"))

    if option == "Generate New Passwords":
        if 'accounts' in st.session_state and st.session_state.accounts:
            st.subheader("Encryption Password")
            encryption_password = st.text_input("Enter encryption password", type="password")
            
            if st.button("Generate Suggested Password"):
                suggested_password = password_manager.generate_encryption_password()
                st.session_state.suggested_password = suggested_password
                st.text_input("Suggested Password", value=suggested_password, key="suggested_password_input")
                if st.button("Use Suggested Password"):
                    encryption_password = suggested_password
            
            if st.button("Generate Passwords"):
                passwords_data, passwords_dict = password_manager.generate_passwords(st.session_state.accounts)
                encrypted_data = password_manager.encrypt_passwords(passwords_data, encryption_password)
                
                # Display generated passwords
                st.subheader("Generated Passwords:")
                for account, password in passwords_dict.items():
                    st.text(f"{account}: {password}")
                    st.text(f"Change password link: {password_manager.get_change_password_link(account)}")
                    st.text("")  # Add a blank line for readability

                # Offer encrypted file for download
                st.download_button(
                    label="Download Encrypted Passwords",
                    data=encrypted_data,
                    file_name="encrypted_passwords.bin",
                    mime="application/octet-stream",
                )
        else:
            st.warning("Please add at least one account before generating passwords.")

    elif option == "Access Existing Passwords":
        uploaded_file = st.file_uploader("Upload encrypted password file", type="bin")
        if uploaded_file is not None:
            decryption_password = st.text_input("Enter decryption password", type="password")
            if st.button("Decrypt Passwords"):
                try:
                    decrypted_data = password_manager.decrypt_passwords(uploaded_file.getvalue(), decryption_password)
                    st.subheader("Decrypted Passwords:")
                    for line in decrypted_data.split('\n'):
                        account, password = line.split(': ')
                        st.text(f"{account}: {password}")
                        st.text(f"Change password link: {password_manager.get_change_password_link(account)}")
                        st.text("")  # Add a blank line for readability
                except Exception as e:
                    st.error("Decryption failed. Please check your password and try again.")

if __name__ == "__main__":
    main()
