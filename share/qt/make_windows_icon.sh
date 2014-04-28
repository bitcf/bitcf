#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/emercoin.png
ICON_DST=../../src/qt/res/icons/emercoin.ico
convert ${ICON_SRC} -resize 16x16 emercoin-16.png
convert ${ICON_SRC} -resize 32x32 emercoin-32.png
convert ${ICON_SRC} -resize 48x48 emercoin-48.png
convert emercoin-16.png emercoin-32.png emercoin-48.png ${ICON_DST}

