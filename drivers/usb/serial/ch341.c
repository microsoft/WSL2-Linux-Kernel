/*
 * Copyright 2007, Frank A Kingswood <frank@kingswood-consulting.co.uk>
 * Copyright 2007, Werner Cornelius <werner@cornelius-consult.de>
 * Copyright 2009, Boris Hajduk <boris@hajduk.org>
 *
 * ch341.c implements a serial port driver for the Winchiphead CH341.
 *
 * The CH341 device can be used to implement an RS232 asynchronous
 * serial port, an IEEE-1284 parallel printer port or a memory-like
 * interface. In all cases the CH341 supports an I2C interface as well.
 * This driver only supports the asynchronous serial interface.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/usb/serial.h>
#include <linux/serial.h>
#include <asm/unaligned.h>

#define DEFAULT_BAUD_RATE 9600
#define DEFAULT_TIMEOUT   1000

/* flags for IO-Bits */
#define CH341_BIT_RTS (1 << 6)
#define CH341_BIT_DTR (1 << 5)

/******************************/
/* interrupt pipe definitions */
/******************************/
/* always 4 interrupt bytes */
/* first irq byte normally 0x08 */
/* second irq byte base 0x7d + below */
/* third irq byte base 0x94 + below */
/* fourth irq byte normally 0xee */

/* second interrupt byte */
#define CH341_MULT_STAT 0x04 /* multiple status since last interrupt event */

/* status returned in third interrupt answer byte, inverted in data
   from irq */
#define CH341_BIT_CTS 0x01
#define CH341_BIT_DSR 0x02
#define CH341_BIT_RI  0x04
#define CH341_BIT_DCD 0x08
#define CH341_BITS_MODEM_STAT 0x0f /* all bits */

/*******************************/
/* baudrate calculation factor */
/*******************************/
#define CH341_BAUDBASE_FACTOR 1532620800
#define CH341_BAUDBASE_DIVMAX 3

/* Break support - the information used to implement this was gleaned from
 * the Net/FreeBSD uchcom.c driver by Takanori Watanabe.  Domo arigato.
 */

#define CH341_REQ_READ_VERSION 0x5F
#define CH341_REQ_WRITE_REG    0x9A
#define CH341_REQ_READ_REG     0x95
#define CH341_REQ_SERIAL_INIT  0xA1
#define CH341_REQ_MODEM_CTRL   0xA4

#define CH341_REG_BREAK        0x05
#define CH341_REG_LCR          0x18
#define CH341_NBREAK_BITS      0x01

#define CH341_LCR_ENABLE_RX    0x80
#define CH341_LCR_ENABLE_TX    0x40
#define CH341_LCR_MARK_SPACE   0x20
#define CH341_LCR_PAR_EVEN     0x10
#define CH341_LCR_ENABLE_PAR   0x08
#define CH341_LCR_STOP_BITS_2  0x04
#define CH341_LCR_CS8          0x03
#define CH341_LCR_CS7          0x02
#define CH341_LCR_CS6          0x01
#define CH341_LCR_CS5          0x00

static int debug;

static const struct usb_device_id id_table[] = {
	{ USB_DEVICE(0x4348, 0x5523) },
	{ USB_DEVICE(0x1a86, 0x7523) },
	{ USB_DEVICE(0x1a86, 0x5523) },
	{ },
};
MODULE_DEVICE_TABLE(usb, id_table);

struct ch341_private {
	spinlock_t lock; /* access lock */
	unsigned baud_rate; /* set baud rate */
	u8 line_control; /* set line control value RTS/DTR */
	u8 line_status; /* active status of modem control inputs */
	u8 multi_status_change; /* status changed multiple since last call */
};

static void ch341_set_termios(struct tty_struct *tty,
			      struct usb_serial_port *port,
			      struct ktermios *old_termios);

static int ch341_control_out(struct usb_device *dev, u8 request,
			     u16 value, u16 index)
{
	int r;
	dbg("ch341_control_out(%02x,%02x,%04x,%04x)", USB_DIR_OUT|0x40,
		(int)request, (int)value, (int)index);

	r = usb_control_msg(dev, usb_sndctrlpipe(dev, 0), request,
			    USB_TYPE_VENDOR | USB_RECIP_DEVICE | USB_DIR_OUT,
			    value, index, NULL, 0, DEFAULT_TIMEOUT);
	if (r < 0)
		dev_err(&dev->dev, "failed to send control message: %d\n", r);

	return r;
}

static int ch341_control_in(struct usb_device *dev,
			    u8 request, u16 value, u16 index,
			    char *buf, unsigned bufsize)
{
	int r;
	dbg("ch341_control_in(%02x,%02x,%04x,%04x,%p,%u)", USB_DIR_IN|0x40,
		(int)request, (int)value, (int)index, buf, (int)bufsize);

	r = usb_control_msg(dev, usb_rcvctrlpipe(dev, 0), request,
			    USB_TYPE_VENDOR | USB_RECIP_DEVICE | USB_DIR_IN,
			    value, index, buf, bufsize, DEFAULT_TIMEOUT);
	if (r < bufsize) {
		if (r >= 0) {
			dev_err(&dev->dev,
				"short control message received (%d < %u)\n",
				r, bufsize);
			r = -EIO;
		}

		dev_err(&dev->dev, "failed to receive control message: %d\n",
			r);
		return r;
	}

	return 0;
}

static int ch341_set_baudrate_lcr(struct usb_device *dev,
				  struct ch341_private *priv, u8 lcr)
{
	short a;
	int r;
	unsigned long factor;
	short divisor;

	dbg("ch341_set_baudrate(%d)", priv->baud_rate);

	if (!priv->baud_rate)
		return -EINVAL;
	factor = (CH341_BAUDBASE_FACTOR / priv->baud_rate);
	divisor = CH341_BAUDBASE_DIVMAX;

	while ((factor > 0xfff0) && divisor) {
		factor >>= 3;
		divisor--;
	}

	if (factor > 0xfff0)
		return -EINVAL;

	factor = 0x10000 - factor;
	a = (factor & 0xff00) | divisor;

	/*
	 * CH341A buffers data until a full endpoint-size packet (32 bytes)
	 * has been received unless bit 7 is set.
	 */
	a |= BIT(7);

	r = ch341_control_out(dev, CH341_REQ_WRITE_REG, 0x1312, a);
	if (r)
		return r;

	r = ch341_control_out(dev, CH341_REQ_WRITE_REG, 0x2518, lcr);
	if (r)
		return r;

	return r;
}

static int ch341_set_handshake(struct usb_device *dev, u8 control)
{
	dbg("ch341_set_handshake(0x%02x)", control);
	return ch341_control_out(dev, CH341_REQ_MODEM_CTRL, ~control, 0);
}

static int ch341_get_status(struct usb_device *dev, struct ch341_private *priv)
{
	const unsigned int size = 2;
	char *buffer;
	int r;
	unsigned long flags;

	dbg("ch341_get_status()");

	buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	r = ch341_control_in(dev, CH341_REQ_READ_REG, 0x0706, 0, buffer, size);
	if (r < 0)
		goto out;

	spin_lock_irqsave(&priv->lock, flags);
	priv->line_status = (~(*buffer)) & CH341_BITS_MODEM_STAT;
	priv->multi_status_change = 0;
	spin_unlock_irqrestore(&priv->lock, flags);

out:	kfree(buffer);
	return r;
}

/* -------------------------------------------------------------------------- */

static int ch341_configure(struct usb_device *dev, struct ch341_private *priv)
{
	const unsigned int size = 2;
	char *buffer;
	int r;

	dbg("ch341_configure()");

	buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	/* expect two bytes 0x27 0x00 */
	r = ch341_control_in(dev, CH341_REQ_READ_VERSION, 0, 0, buffer, size);
	if (r < 0)
		goto out;

	r = ch341_control_out(dev, CH341_REQ_SERIAL_INIT, 0, 0);
	if (r < 0)
		goto out;

	/* expect two bytes 0x56 0x00 */
	r = ch341_control_in(dev, CH341_REQ_READ_REG, 0x2518, 0, buffer, size);
	if (r < 0)
		goto out;

	r = ch341_control_out(dev, CH341_REQ_WRITE_REG, 0x2518, 0x0050);
	if (r < 0)
		goto out;

	/* expect 0xff 0xee */
	r = ch341_get_status(dev, priv);
	if (r < 0)
		goto out;

	r = ch341_set_baudrate_lcr(dev, priv, 0);
	if (r < 0)
		goto out;

	r = ch341_set_handshake(dev, priv->line_control);
	if (r < 0)
		goto out;

	/* expect 0x9f 0xee */
	r = ch341_get_status(dev, priv);

out:	kfree(buffer);
	return r;
}

/* allocate private data */
static int ch341_attach(struct usb_serial *serial)
{
	struct ch341_private *priv;
	int r;

	dbg("ch341_attach()");

	/* private data */
	priv = kzalloc(sizeof(struct ch341_private), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	spin_lock_init(&priv->lock);
	priv->baud_rate = DEFAULT_BAUD_RATE;

	r = ch341_configure(serial->dev, priv);
	if (r < 0)
		goto error;

	usb_set_serial_port_data(serial->port[0], priv);
	return 0;

error:	kfree(priv);
	return r;
}

static int ch341_carrier_raised(struct usb_serial_port *port)
{
	struct ch341_private *priv = usb_get_serial_port_data(port);
	if (priv->line_status & CH341_BIT_DCD)
		return 1;
	return 0;
}

static void ch341_dtr_rts(struct usb_serial_port *port, int on)
{
	struct ch341_private *priv = usb_get_serial_port_data(port);
	unsigned long flags;

	dbg("%s - port %d", __func__, port->number);
	/* drop DTR and RTS */
	spin_lock_irqsave(&priv->lock, flags);
	if (on)
		priv->line_control |= CH341_BIT_RTS | CH341_BIT_DTR;
	else
		priv->line_control &= ~(CH341_BIT_RTS | CH341_BIT_DTR);
	spin_unlock_irqrestore(&priv->lock, flags);
	ch341_set_handshake(port->serial->dev, priv->line_control);
	wake_up_interruptible(&port->delta_msr_wait);
}

static void ch341_close(struct usb_serial_port *port)
{
	dbg("%s - port %d", __func__, port->number);

	usb_serial_generic_close(port);
	usb_kill_urb(port->interrupt_in_urb);
}


/* open this device, set default parameters */
static int ch341_open(struct tty_struct *tty, struct usb_serial_port *port)
{
	struct usb_serial *serial = port->serial;
	struct ch341_private *priv = usb_get_serial_port_data(serial->port[0]);
	int r;

	dbg("ch341_open()");

	r = ch341_configure(serial->dev, priv);
	if (r)
		return r;

	if (tty)
		ch341_set_termios(tty, port, NULL);

	dbg("%s - submitting interrupt urb", __func__);
	port->interrupt_in_urb->dev = serial->dev;
	r = usb_submit_urb(port->interrupt_in_urb, GFP_KERNEL);
	if (r) {
		dev_err(&port->dev, "%s - failed submitting interrupt urb,"
			" error %d\n", __func__, r);
		return r;
	}

	r = usb_serial_generic_open(tty, port);
	if (r)
		goto err_kill_interrupt_urb;

	return 0;

err_kill_interrupt_urb:
	usb_kill_urb(port->interrupt_in_urb);

	return r;
}

/* Old_termios contains the original termios settings and
 * tty->termios contains the new setting to be used.
 */
static void ch341_set_termios(struct tty_struct *tty,
		struct usb_serial_port *port, struct ktermios *old_termios)
{
	struct ch341_private *priv = usb_get_serial_port_data(port);
	unsigned baud_rate;
	unsigned long flags;
	unsigned char ctrl;
	int r;

	/* redundant changes may cause the chip to lose bytes */
	if (old_termios && !tty_termios_hw_change(tty->termios, old_termios))
		return;

	dbg("ch341_set_termios()");

	baud_rate = tty_get_baud_rate(tty);

	ctrl = CH341_LCR_ENABLE_RX | CH341_LCR_ENABLE_TX | CH341_LCR_CS8;

	if (baud_rate) {
		priv->baud_rate = baud_rate;

		r = ch341_set_baudrate_lcr(port->serial->dev, priv, ctrl);
		if (r < 0 && old_termios) {
			priv->baud_rate = tty_termios_baud_rate(old_termios);
			tty_termios_copy_hw(tty->termios, old_termios);
		}
	}

	spin_lock_irqsave(&priv->lock, flags);
	if (C_BAUD(tty) == B0)
		priv->line_control &= ~(CH341_BIT_DTR | CH341_BIT_RTS);
	else if (old_termios && (old_termios->c_cflag & CBAUD) == B0)
		priv->line_control |= (CH341_BIT_DTR | CH341_BIT_RTS);
	spin_unlock_irqrestore(&priv->lock, flags);

	/* Unimplemented:
	 * (cflag & CSIZE) : data bits [5, 8]
	 * (cflag & PARENB) : parity {NONE, EVEN, ODD}
	 * (cflag & CSTOPB) : stop bits [1, 2]
	 */
}

static void ch341_break_ctl(struct tty_struct *tty, int break_state)
{
	const uint16_t ch341_break_reg =
			((uint16_t) CH341_REG_LCR << 8) | CH341_REG_BREAK;
	struct usb_serial_port *port = tty->driver_data;
	int r;
	uint16_t reg_contents;
	uint8_t *break_reg;

	dbg("%s()", __func__);

	break_reg = kmalloc(2, GFP_KERNEL);
	if (!break_reg) {
		dev_err(&port->dev, "%s - kmalloc failed\n", __func__);
		return;
	}

	r = ch341_control_in(port->serial->dev, CH341_REQ_READ_REG,
			ch341_break_reg, 0, break_reg, 2);
	if (r < 0) {
		dev_err(&port->dev, "%s - USB control read error (%d)\n",
				__func__, r);
		goto out;
	}
	dbg("%s - initial ch341 break register contents - reg1: %x, reg2: %x",
			__func__, break_reg[0], break_reg[1]);
	if (break_state != 0) {
		dbg("%s - Enter break state requested", __func__);
		break_reg[0] &= ~CH341_NBREAK_BITS;
		break_reg[1] &= ~CH341_LCR_ENABLE_TX;
	} else {
		dbg("%s - Leave break state requested", __func__);
		break_reg[0] |= CH341_NBREAK_BITS;
		break_reg[1] |= CH341_LCR_ENABLE_TX;
	}
	dbg("%s - New ch341 break register contents - reg1: %x, reg2: %x",
			__func__, break_reg[0], break_reg[1]);
	reg_contents = get_unaligned_le16(break_reg);
	r = ch341_control_out(port->serial->dev, CH341_REQ_WRITE_REG,
			ch341_break_reg, reg_contents);
	if (r < 0)
		dev_err(&port->dev, "%s - USB control write error (%d)\n",
				__func__, r);
out:
	kfree(break_reg);
}

static int ch341_tiocmset(struct tty_struct *tty,
			  unsigned int set, unsigned int clear)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ch341_private *priv = usb_get_serial_port_data(port);
	unsigned long flags;
	u8 control;

	spin_lock_irqsave(&priv->lock, flags);
	if (set & TIOCM_RTS)
		priv->line_control |= CH341_BIT_RTS;
	if (set & TIOCM_DTR)
		priv->line_control |= CH341_BIT_DTR;
	if (clear & TIOCM_RTS)
		priv->line_control &= ~CH341_BIT_RTS;
	if (clear & TIOCM_DTR)
		priv->line_control &= ~CH341_BIT_DTR;
	control = priv->line_control;
	spin_unlock_irqrestore(&priv->lock, flags);

	return ch341_set_handshake(port->serial->dev, control);
}

static void ch341_read_int_callback(struct urb *urb)
{
	struct usb_serial_port *port = (struct usb_serial_port *) urb->context;
	unsigned char *data = urb->transfer_buffer;
	unsigned int actual_length = urb->actual_length;
	int status;

	dbg("%s (%d)", __func__, port->number);

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __func__,
		    urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __func__,
		    urb->status);
		goto exit;
	}

	usb_serial_debug_data(debug, &port->dev, __func__,
			      urb->actual_length, urb->transfer_buffer);

	if (actual_length >= 4) {
		struct ch341_private *priv = usb_get_serial_port_data(port);
		unsigned long flags;
		u8 prev_line_status = priv->line_status;

		spin_lock_irqsave(&priv->lock, flags);
		priv->line_status = (~(data[2])) & CH341_BITS_MODEM_STAT;
		if ((data[1] & CH341_MULT_STAT))
			priv->multi_status_change = 1;
		spin_unlock_irqrestore(&priv->lock, flags);

		if ((priv->line_status ^ prev_line_status) & CH341_BIT_DCD) {
			struct tty_struct *tty = tty_port_tty_get(&port->port);
			if (tty)
				usb_serial_handle_dcd_change(port, tty,
					    priv->line_status & CH341_BIT_DCD);
			tty_kref_put(tty);
		}

		wake_up_interruptible(&port->delta_msr_wait);
	}

exit:
	status = usb_submit_urb(urb, GFP_ATOMIC);
	if (status)
		dev_err(&urb->dev->dev,
			"%s - usb_submit_urb failed with result %d\n",
			__func__, status);
}

static int wait_modem_info(struct usb_serial_port *port, unsigned int arg)
{
	struct ch341_private *priv = usb_get_serial_port_data(port);
	unsigned long flags;
	u8 prevstatus;
	u8 status;
	u8 changed;
	u8 multi_change = 0;

	spin_lock_irqsave(&priv->lock, flags);
	prevstatus = priv->line_status;
	priv->multi_status_change = 0;
	spin_unlock_irqrestore(&priv->lock, flags);

	while (!multi_change) {
		interruptible_sleep_on(&port->delta_msr_wait);
		/* see if a signal did it */
		if (signal_pending(current))
			return -ERESTARTSYS;

		if (port->serial->disconnected)
			return -EIO;

		spin_lock_irqsave(&priv->lock, flags);
		status = priv->line_status;
		multi_change = priv->multi_status_change;
		spin_unlock_irqrestore(&priv->lock, flags);

		changed = prevstatus ^ status;

		if (((arg & TIOCM_RNG) && (changed & CH341_BIT_RI)) ||
		    ((arg & TIOCM_DSR) && (changed & CH341_BIT_DSR)) ||
		    ((arg & TIOCM_CD)  && (changed & CH341_BIT_DCD)) ||
		    ((arg & TIOCM_CTS) && (changed & CH341_BIT_CTS))) {
			return 0;
		}
		prevstatus = status;
	}

	return 0;
}

static int ch341_ioctl(struct tty_struct *tty,
			unsigned int cmd, unsigned long arg)
{
	struct usb_serial_port *port = tty->driver_data;
	dbg("%s (%d) cmd = 0x%04x", __func__, port->number, cmd);

	switch (cmd) {
	case TIOCMIWAIT:
		dbg("%s (%d) TIOCMIWAIT", __func__,  port->number);
		return wait_modem_info(port, arg);

	default:
		dbg("%s not supported = 0x%04x", __func__, cmd);
		break;
	}

	return -ENOIOCTLCMD;
}

static int ch341_tiocmget(struct tty_struct *tty)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ch341_private *priv = usb_get_serial_port_data(port);
	unsigned long flags;
	u8 mcr;
	u8 status;
	unsigned int result;

	dbg("%s (%d)", __func__, port->number);

	spin_lock_irqsave(&priv->lock, flags);
	mcr = priv->line_control;
	status = priv->line_status;
	spin_unlock_irqrestore(&priv->lock, flags);

	result = ((mcr & CH341_BIT_DTR)		? TIOCM_DTR : 0)
		  | ((mcr & CH341_BIT_RTS)	? TIOCM_RTS : 0)
		  | ((status & CH341_BIT_CTS)	? TIOCM_CTS : 0)
		  | ((status & CH341_BIT_DSR)	? TIOCM_DSR : 0)
		  | ((status & CH341_BIT_RI)	? TIOCM_RI  : 0)
		  | ((status & CH341_BIT_DCD)	? TIOCM_CD  : 0);

	dbg("%s - result = %x", __func__, result);

	return result;
}


static int ch341_reset_resume(struct usb_interface *intf)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	struct usb_serial *serial = usb_get_intfdata(intf);
	struct usb_serial_port *port = serial->port[0];
	struct ch341_private *priv = usb_get_serial_port_data(port);
	int ret;

	/*reconfigure ch341 serial port after bus-reset*/
	ch341_configure(dev, priv);

	if (port->port.flags & ASYNC_INITIALIZED) {
		ret = usb_submit_urb(port->interrupt_in_urb, GFP_NOIO);
		if (ret) {
			dev_err(&port->dev, "failed to submit interrupt urb: %d\n",
				ret);
			return ret;
		}
	}

	return usb_serial_generic_resume(serial);
}

static struct usb_driver ch341_driver = {
	.name		= "ch341",
	.probe		= usb_serial_probe,
	.disconnect	= usb_serial_disconnect,
	.suspend	= usb_serial_suspend,
	.resume		= usb_serial_resume,
	.reset_resume	= ch341_reset_resume,
	.id_table	= id_table,
	.no_dynamic_id	= 1,
	.supports_autosuspend =	1,
};

static struct usb_serial_driver ch341_device = {
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "ch341-uart",
	},
	.id_table          = id_table,
	.usb_driver        = &ch341_driver,
	.num_ports         = 1,
	.open              = ch341_open,
	.dtr_rts	   = ch341_dtr_rts,
	.carrier_raised	   = ch341_carrier_raised,
	.close             = ch341_close,
	.ioctl             = ch341_ioctl,
	.set_termios       = ch341_set_termios,
	.break_ctl         = ch341_break_ctl,
	.tiocmget          = ch341_tiocmget,
	.tiocmset          = ch341_tiocmset,
	.read_int_callback = ch341_read_int_callback,
	.attach            = ch341_attach,
};

static int __init ch341_init(void)
{
	int retval;

	retval = usb_serial_register(&ch341_device);
	if (retval)
		return retval;
	retval = usb_register(&ch341_driver);
	if (retval)
		usb_serial_deregister(&ch341_device);
	return retval;
}

static void __exit ch341_exit(void)
{
	usb_deregister(&ch341_driver);
	usb_serial_deregister(&ch341_device);
}

module_init(ch341_init);
module_exit(ch341_exit);
MODULE_LICENSE("GPL");

module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Debug enabled or not");

/* EOF ch341.c */
