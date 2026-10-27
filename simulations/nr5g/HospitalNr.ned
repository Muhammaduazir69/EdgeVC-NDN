package simulations.nr5g;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.networklayer.ipv4.RoutingTableRecorder;
import inet.node.ethernet.Eth10G;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import simu5g.common.binder.Binder;
import simu5g.common.carrierAggregation.CarrierAggregation;
import simu5g.nodes.Upf;
import simu5g.nodes.NR.gNodeB;
import simu5g.nodes.NR.NRUe;
import simu5g.world.radio.LteChannelControl;
import ned.SimulationManager;

//
// Hospital 5G standalone cell (Simu5G). Clinician UEs reach the NDN edge
// (verifier, PRE proxy, content store) on an edge server in the local data
// network behind the UPF's N6 interface. The EHR producer, the credential
// issuer, the central PDP and one ledger validator run in the hospital data
// center behind the core router; three further validators sit at partner
// sites. Every NDN node is an INET application speaking NDN over UDP.
//
network HospitalNr
{
    parameters:
        int numUe = default(10);
        int numAttackers = default(0);
        double dcDelay @unit(s) = default(5ms);
        double siteDelay @unit(s) = default(10ms);
        double mecDelay @unit(s) = default(0.1ms);
        @display("i=block/network2;bgb=1200,800");
    submodules:
        channelControl: LteChannelControl { @display("p=50,25;is=s"); }
        routingRecorder: RoutingTableRecorder { @display("p=50,75;is=s"); }
        configurator: Ipv4NetworkConfigurator { @display("p=50,125"); config = xmldoc("demo.xml"); }
        binder: Binder { @display("p=50,175;is=s"); }
        carrierAggregation: CarrierAggregation { @display("p=50,258;is=s"); }
        simManager: SimulationManager { @display("p=50,330"); }
        dcHost: StandardHost { @display("p=150,150;i=device/server"); }
        siteHost[3]: StandardHost { @display("p=150,330,c,110;i=device/server2"); }
        router: Router { @display("p=330,150;i=device/smallrouter"); }
        upf: Upf { @display("p=500,150"); }
        iUpf: Upf { @display("p=680,150"); }
        mecHost: StandardHost { @display("p=330,40;i=device/server,gold"); }
        gnb: gNodeB { @display("p=820,300;is=vl"); }
        ue[numUe]: NRUe { @display("p=820,520"); }
        ueAtk[numAttackers]: NRUe { @display("p=980,520;i=device/cellphone,red"); }
    connections allowunconnected:
        dcHost.pppg++ <--> Eth10G { delay = parent.dcDelay; } <--> router.pppg++;
        for i=0..2 {
            siteHost[i].pppg++ <--> Eth10G { delay = parent.siteDelay; } <--> router.pppg++;
        }
        router.pppg++ <--> Eth10G <--> upf.filterGate;
        upf.pppg++ <--> Eth10G <--> iUpf.pppg++;
        iUpf.pppg++ <--> Eth10G <--> gnb.ppp;
        // Edge server in the local data network on the UPF's N6 side.
        mecHost.pppg++ <--> Eth10G { delay = parent.mecDelay; } <--> router.pppg++;
}
