/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010-2011 Andrey Churin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Andrey Churin <aachurin@gmail.com>
  */
 
#ifndef ETHERNET_NET_DEVICE_H
#define ETHERNET_NET_DEVICE_H

#include <string.h>
#include "ns3/node.h"
#include "ns3/address.h"
#include "ns3/net-device.h"
#include "ns3/callback.h"
#include "ns3/packet.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/data-rate.h"
#include "ns3/ptr.h"
#include "ns3/random-variable.h"
#include "ns3/mac48-address.h"

namespace ns3 {

class Queue;
class CsmaChannel;
class ErrorModel;

/**
 * \class EthernetNetDevice
 * \brief A Device for a Ethernet Network Link.
 *
 * The Ethernet net device class is analogous to layer 1 and 2 of the
 * TCP stack. The NetDevice takes a raw packet of bytes and creates a
 * protocol specific packet from them. 
 */
class EthernetNetDevice : public NetDevice 
{
public:
  static TypeId GetTypeId (void);

  /**
   * Construct a EthernetNetDevice
   *
   * This is the default constructor for a EthernetNetDevice.
   */
  EthernetNetDevice ();

  /**
   * Destroy a EthernetNetDevice
   *
   * This is the destructor for a EthernetNetDevice.
   */
  virtual ~EthernetNetDevice ();

  /**
   * Set the interframe gap used to separate packets.  The interframe gap
   * defines the minimum space required between packets sent by this device.
   * It defaults to 96 bit times.
   *
   * @param t the interframe gap time
   */
  void SetInterframeGap (Time t);

  /**
   * Attach the device to a channel.
   *
   * The function Attach is used to add a EthernetNetDevice to a CsmaChannel's.
   *
   * @param tx the channel for transmitting
   * @param rx the channel for receiving   
   */
  bool Attach (const Ptr<CsmaChannel> &tx, const Ptr<CsmaChannel> &rx);

  /**
   * Attach a queue to the EthernetNetDevice.
   *
   * The EthernetNetDevice "owns" a queue.  This queue may be set by higher
   * level topology objects to implement a particular queueing method such as
   * DropTail or RED.  
   *
   * @param queue the queue for being assigned to the device.
   */
  void SetQueue (const Ptr<Queue> &queue);

  /**
   * Get the attached Queue.
   */
  Ptr<Queue> GetQueue (void) const; 

  /**
   * Attach a receive ErrorModel to the EthernetNetDevice.
   *
   * The EthernetNetDevice may optionally include an ErrorModel in
   * the packet receive chain to simulate data errors in during transmission.
   *
   * @param em the ErrorModel 
   */
  void SetReceiveErrorModel (const Ptr<ErrorModel> &em);

  /**
   * Set the encapsulation mode of this device.
   *
   * @param mode The encapsulation mode of this device.
   *
   */
  void SetEncapsulationMode (CsmaNetDevice::EncapsulationMode mode);

  /**
   * Get the encapsulation mode of this device.
   *
   * @return The encapsulation mode of this device.
   */
  CsmaNetDevice::EncapsulationMode GetEncapsulationMode (void) const;

  //
  // The following methods are inherited from NetDevice base class.
  //
  virtual void SetIfIndex (const uint32_t index);
  virtual uint32_t GetIfIndex (void) const;
  virtual Ptr<Channel> GetChannel (void) const;
  virtual bool SetMtu (const uint16_t mtu);
  virtual uint16_t GetMtu (void) const;
  virtual void SetAddress (Address address);
  virtual Address GetAddress (void) const;
  virtual bool IsLinkUp (void) const;
  virtual void AddLinkChangeCallback (Callback<void> callback);
  virtual bool IsBroadcast (void) const;
  virtual Address GetBroadcast (void) const;
  virtual bool IsMulticast (void) const;

  /**
   * @brief Make and return a MAC multicast address using the provided
   *        multicast group
   *
   * @param multicastGroup The IP address for the multicast group destination of the packet.
   * @return The MAC multicast Address used to send packets to the provided multicast group.
   */
  virtual Address GetMulticast (Ipv4Address multicastGroup) const;

  /**
   * @brief Is this a point to point link?
   * @return false.
   */
  virtual bool IsPointToPoint (void) const;

  /**
   * @brief Is this a bridge?
   * @return false.
   */
  virtual bool IsBridge (void) const;

  /**
   * @brief Start sending a packet down the channel.
   * @param packet packet to send
   * @param dest layer 2 destination address
   * @param protocolNumber protocol number
   * @return true if successfull, false otherwise (drop, ...)
   */
  virtual bool Send (Ptr<Packet> packet, const Address& dest, 
                        uint16_t protocolNumber);

  /**
   * @brief Start sending a packet down the channel, with MAC spoofing
   * @param packet packet to send
   * @param source layer 2 source address
   * @param dest layer 2 destination address
   * @param protocolNumber protocol number
   * @return true if successfull, false otherwise (drop, ...)
   */
  virtual bool SendFrom (Ptr<Packet> packet, const Address& source, const Address& dest, 
                         uint16_t protocolNumber);

  /**
   * @brief Get the node to which this device is attached.
   * @return Ptr to the Node to which the device is attached.
   */
  virtual Ptr<Node> GetNode (void) const;

  /**
   * @brief Set the node to which this device is being attached.
   * @param node Ptr to the Node to which the device is being attached.
   */
  virtual void SetNode (Ptr<Node> node);

  /**
   * Does this device need to use the address resolution protocol?
   *
   * @return True if the encapsulation mode is set to a value that requires
   * ARP (IP_ARP or LLC).
   */
  virtual bool NeedsArp (void) const;

  /**
   * Set the callback to be used to notify higher layers when a packet has been
   * received.
   *
   * @param cb The callback.
   */
  virtual void SetReceiveCallback (NetDevice::ReceiveCallback cb);

  /**
   * @brief Get the MAC multicast address corresponding to the IPv6 address provided.
   * @param addr IPv6 address
   * @return the MAC multicast address
   */
  virtual Address GetMulticast (Ipv6Address addr) const;


  virtual void SetPromiscReceiveCallback (PromiscReceiveCallback cb);
  virtual bool SupportsSendFrom (void) const;

protected:
  /**
   * Perform any object release functionality required to break reference 
   * cycles in reference counted objects held by the device.
   */
  virtual void DoDispose (void);

private:

  /**
   * Operator = is declared but not implemented.  This disables the assignment
   * operator for EthernetNetDevice objects.
   * \param o object to copy
   */
  EthernetNetDevice &operator = (const EthernetNetDevice &o);

  /**
   * Copy constructor is declared but not implemented.  This disables the
   * copy constructor for EthernetNetDevice objects.
   * \param o object to copy
   */
  EthernetNetDevice (const EthernetNetDevice &o);
  
  /** 
   * Device ID returned by the attached functions. It is used by the
   * mp-channel to identify each net device to make sure that only
   * active net devices are writing to the channel
   */
  uint32_t m_deviceId; 

  /**
   * The trace source fired when packets coming into the "top" of the device
   * at the L3/L2 transition are dropped before being queued for transmission.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_macTxDropTrace;

  /**
   * The trace source fired for packets successfully received by the device
   * immediately before being forwarded up to higher layers (at the L2/L3 
   * transition).  This is a promiscuous trace.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_macPromiscRxTrace;

  /**
   * The trace source fired for packets successfully received by the device
   * immediately before being forwarded up to higher layers (at the L2/L3 
   * transition).  This is a non-promiscuous trace.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_macRxTrace;

  /**
   * The trace source fired for packets successfully received by the device
   * but dropped before being forwarded up to higher layers (at the L2/L3 
   * transition).
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_macRxDropTrace;

  /**
   * The trace source fired when the mac layer is forced to begin the backoff
   * process for a packet.  This can happen a number of times as the backoff
   * sequence is repeated with increasing delays.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_macTxBackoffTrace;

  /**
   * The trace source fired when a packet begins the transmission process on
   * the medium.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_phyTxBeginTrace;

  /**
   * The trace source fired when a packet ends the transmission process on
   * the medium.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_phyTxEndTrace;

  /**
   * The trace source fired when the phy layer drops a packet as it tries
   * to transmit it.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_phyTxDropTrace;

  /**
   * The trace source fired when a packet begins the reception process from
   * the medium.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_phyRxBeginTrace;

  /**
   * The trace source fired when a packet ends the reception process from
   * the medium.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_phyRxEndTrace;

  /**
   * The trace source fired when the phy layer drops a packet it has received.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_phyRxDropTrace;

  /**
   * A trace source that emulates a non-promiscuous protocol sniffer connected 
   * to the device.  Unlike your average everyday sniffer, this trace source 
   * will not fire on PACKET_OTHERHOST events.
   *
   * On the transmit size, this trace hook will fire after a packet is dequeued
   * from the device queue for transmission.  In Linux, for example, this would
   * correspond to the point just before a device hard_start_xmit where 
   * dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET 
   * ETH_P_ALL handlers.
   *
   * On the receive side, this trace hook will fire when a packet is received,
   * just before the receive callback is executed.  In Linux, for example, 
   * this would correspond to the point at which the packet is dispatched to 
   * packet sniffers in netif_receive_skb.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_snifferTrace;

  /**
   * A trace source that emulates a promiscuous mode protocol sniffer connected
   * to the device.  This trace source fire on packets destined for any host
   * just like your average everyday packet sniffer.
   *
   * On the transmit size, this trace hook will fire after a packet is dequeued
   * from the device queue for transmission.  In Linux, for example, this would
   * correspond to the point just before a device hard_start_xmit where 
   * dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET 
   * ETH_P_ALL handlers.
   *
   * On the receive side, this trace hook will fire when a packet is received,
   * just before the receive callback is executed.  In Linux, for example, 
   * this would correspond to the point at which the packet is dispatched to 
   * packet sniffers in netif_receive_skb.
   *
   * \see class CallBackTraceSource
   */
  TracedCallback<Ptr<const Packet> > m_promiscSnifferTrace;

  /**
   * The MAC address which has been assigned to this device.
   */
  Mac48Address m_address;

  /**
   * The callback used to notify higher layers that a packet has been received.
   */
  NetDevice::ReceiveCallback m_rxCallback;

  /**
   * The callback used to notify higher layers that a packet has been received in promiscuous mode.
   */
  NetDevice::PromiscReceiveCallback m_promiscRxCallback;

  /**
   * The interface index (really net evice index) that has been assigned to 
   * this network device.
   */
  uint32_t m_ifIndex;

  /**
   * Flag indicating whether or not the link is up.  In this case,
   * whether or not the device is connected to a channel.
   */
  bool m_linkUp;

  /**
   * List of callbacks to fire if the link changes state (up or down).
   */
  TracedCallback<> m_linkChangeCallbacks;

  static const uint16_t DEFAULT_MTU = 1500;

  /**
   * The Maximum Transmission Unit.  This corresponds to the maximum 
   * number of bytes that can be transmitted as seen from higher layers.
   * This corresponds to the 1500 byte MTU size often seen on IP over 
   * Ethernet.
   */
  uint32_t m_mtu;
};

}; // namespace ns3

#endif // CSMA_NET_DEVICE_H
