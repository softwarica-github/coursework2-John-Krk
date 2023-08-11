import unittest
from wallet_app import User, Wallet

class TestUserTransaction(unittest.TestCase):

    def test_send_transaction(self):
        # Create sender and recipient users with wallets
        sender_wallet = Wallet(None)  # You may need to provide a Web3 instance here
        recipient_wallet = Wallet(None)  # You may need to provide a Web3 instance here
        sender = User('123456', 'Sender User', sender_wallet)
        recipient = User('789012', 'Recipient User', recipient_wallet)

        # Initial balances before transaction
        sender_initial_balance = sender.balance
        recipient_initial_balance = recipient.balance

        # Send a transaction from sender to recipient
        transaction_amount = 2.5
        sender.send_transaction(recipient, transaction_amount)

        # Expected balances after transaction
        sender_expected_balance = sender_initial_balance - transaction_amount
        recipient_expected_balance = recipient_initial_balance + transaction_amount

        # Check if balances have been updated correctly
        self.assertEqual(sender.balance, sender_expected_balance)
        self.assertEqual(recipient.balance, recipient_expected_balance)

if __name__ == '__main__':
    unittest.main()
