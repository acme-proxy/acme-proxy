#!/bin/bash

certbot \
	--server http://localhost:3000/profile/default/directory \
	--config-dir data/etc \
	--work-dir data/lib \
	--logs-dir data/logs \
	$*

