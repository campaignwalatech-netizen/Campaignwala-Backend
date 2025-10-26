const Wallet = require('./wallet.model');
const User = require('../users/user.model');

// Get wallet by user ID
const getWalletByUserId = async (req, res) => {
  try {
    const { userId } = req.params;

    let wallet = await Wallet.findOne({ userId }).populate('userId', 'name phoneNumber email');

    // If wallet doesn't exist, create one
    if (!wallet) {
      wallet = new Wallet({ userId });
      await wallet.save();
      await wallet.populate('userId', 'name phoneNumber email');
    }

    res.status(200).json({
      success: true,
      data: wallet
    });
  } catch (error) {
    console.error('Error fetching wallet:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch wallet',
      error: error.message
    });
  }
};

// Add credit to wallet (commission from lead approval)
const addCredit = async (req, res) => {
  try {
    const { userId, amount, description, leadId } = req.body;

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID or amount'
      });
    }

    let wallet = await Wallet.findOne({ userId });

    // If wallet doesn't exist, create one
    if (!wallet) {
      wallet = new Wallet({ userId });
    }

    // Add credit transaction
    wallet.balance += parseFloat(amount);
    wallet.totalEarned += parseFloat(amount);
    wallet.transactions.push({
      type: 'credit',
      amount: parseFloat(amount),
      description: description || 'Commission credited',
      leadId: leadId || null
    });

    await wallet.save();
    await wallet.populate('userId', 'name phoneNumber email');

    res.status(200).json({
      success: true,
      message: 'Credit added successfully',
      data: wallet
    });
  } catch (error) {
    console.error('Error adding credit:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add credit',
      error: error.message
    });
  }
};

// Add debit to wallet (withdrawal)
const addDebit = async (req, res) => {
  try {
    const { userId, amount, description } = req.body;

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID or amount'
      });
    }

    let wallet = await Wallet.findOne({ userId });

    if (!wallet) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found'
      });
    }

    if (wallet.balance < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    // Add debit transaction
    wallet.balance -= parseFloat(amount);
    wallet.totalWithdrawn += parseFloat(amount);
    wallet.transactions.push({
      type: 'debit',
      amount: parseFloat(amount),
      description: description || 'Withdrawal'
    });

    await wallet.save();
    await wallet.populate('userId', 'name phoneNumber email');

    res.status(200).json({
      success: true,
      message: 'Debit processed successfully',
      data: wallet
    });
  } catch (error) {
    console.error('Error processing debit:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process debit',
      error: error.message
    });
  }
};

// Get all wallets (Admin only)
const getAllWallets = async (req, res) => {
  try {
    const wallets = await Wallet.find().populate('userId', 'name phoneNumber email role');

    res.status(200).json({
      success: true,
      data: wallets
    });
  } catch (error) {
    console.error('Error fetching wallets:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch wallets',
      error: error.message
    });
  }
};

module.exports = {
  getWalletByUserId,
  addCredit,
  addDebit,
  getAllWallets
};
