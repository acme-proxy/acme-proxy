#!/bin/bash

certbot \
	--server http://localhost:3000/endpoint/default/directory \
	--config-dir data/etc \
	--work-dir data/lib \
	--logs-dir data/logs \
	$*

