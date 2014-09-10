#ifndef GUICONSTANTS_H
#define GUICONSTANTS_H

/* Milliseconds between model updates */
static const int MODEL_UPDATE_DELAY = 2000;

/* Maximum  passphrase length */
static const int MAX_PASSPHRASE_SIZE = 1024;

/* Size of icons in status bar */
static const int STATUSBAR_ICONSIZE = 16;

/* Invalid field background style */
#define STYLE_INVALID "background:#FF8080"

/* Transaction list -- unconfirmed transaction */
#define COLOR_UNCONFIRMED QColor(128, 128, 128)
/* Transaction list -- negative amount */
#define COLOR_NEGATIVE QColor(255, 0, 0)
/* Transaction list -- bare address (without label) */
#define COLOR_BAREADDRESS QColor(140, 140, 140)

// Should be set to MAX_VALUE_LENGTH (from namecoin.h) when it's supported by the network
// (currently due to limitations of CScript the limit is 519 bytes)
static const int GUI_MAX_VALUE_LENGTH = 519;

#endif // GUICONSTANTS_H
