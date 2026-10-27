package simulations.campus;

import ned.AuthzServer;
import ned.Consumer;
import ned.Issuer;
import ned.Producer;
import ned.Router;
import ned.SimulationManager;

//
// Hospital campus used by every framework (the framework is the only factor
// that changes between runs). Data center: EHR producer, credential issuer,
// central PDP (ABAC) and one ledger validator, behind a data-center router
// reached over a metro link of delay dcDelay. Campus: backbone, three
// building cores, two edge routers per building (paired by a redundancy
// link). Three further validators sit at the building cores, as a
// consortium ledger would place its peers. Clinicians attach to the edges.
//
network HospitalCampus
{
    parameters:
        int numConsumers = default(15);
        int numAttackers = default(0);
        int numEdge = default(6);
        int numCore = default(3);
        int numValidators = default(4);
        double dcDelay @unit(s) = default(2ms);
        double coreDelay @unit(s) = default(1ms);
        double edgeDelay @unit(s) = default(1ms);
        double accessDelay @unit(s) = default(0.5ms);
        double accessRate @unit(bps) = default(100Mbps);
        double linkPer = default(0);       // packet error rate on metro/campus/access links
        @display("bgb=1480,800;bgg=100,1,grey95");

    types:
        channel Lan extends ned.DatarateChannel { delay = 0.1ms; datarate = 10Gbps; }
        channel Metro extends ned.DatarateChannel { datarate = 10Gbps; per = parent.linkPer; }
        channel Campus extends ned.DatarateChannel { datarate = 1Gbps; per = parent.linkPer; }
        channel Access extends ned.DatarateChannel { per = parent.linkPer; }

    submodules:
        simManager: SimulationManager { @display("p=60,40;is=s"); }
        producer: Producer { @display("p=520,50;i=device/server2,green"); }
        issuer: Issuer { @display("p=660,50;i=device/server,red"); }
        pdp: AuthzServer { mode = "pdp"; @display("p=800,50;i=block/encrypt,orange"); }
        validator[numValidators]: AuthzServer { mode = "validator"; @display("p=960,50,r,120;i=block/encrypt,green"); }
        dcRouter: Router { @display("p=660,150;i=abstract/router,gold"); }
        backbone: Router { @display("p=660,260;i=abstract/router,gold"); }
        core[numCore]: Router { @display("p=250,370,r,410;i=abstract/router,purple"); }
        edge[numEdge]: Router { @display("p=125,500,r,226;i=abstract/router,blue"); }
        consumer[numConsumers]: Consumer {
            userRole = choose(index % 15, "Attending Resident Nurse Attending Nurse Radiologist LabTechnician Pharmacist Nurse Attending Nurse Surgeon Anesthesiologist Receptionist Administrator");
            unit = choose(index % 15, "ICU ICU ICU Emergency Emergency Radiology Radiology Pharmacy Surgery Oncology Oncology Surgery Surgery Reception Administration");
            clearance = int(choose(index % 15, "4 3 3 4 3 3 2 3 3 4 3 4 4 1 1"));
            px = 125 + int(choose(index % 15, "0 0 0 1 1 2 2 3 4 3 3 4 4 5 5")) * 226 + (int(choose(index % 15, "0 1 2 0 1 0 1 0 0 1 2 1 2 0 1")) - 1) * 62 + int(index / 15) * 14;
            py = 640 + int(index / 15) * 12;
        }
        attacker[numAttackers]: Consumer { px = 240 + index * 226; py = 760; @display("i=device/laptop,red"); }

    connections allowunconnected:
        producer.port++ <--> Lan <--> dcRouter.port++;
        issuer.port++ <--> Lan <--> dcRouter.port++;
        pdp.port++ <--> Lan <--> dcRouter.port++;
        validator[0].port++ <--> Lan <--> dcRouter.port++;
        dcRouter.port++ <--> Metro { delay = parent.dcDelay; } <--> backbone.port++;
        for i=0..numCore-1 {
            backbone.port++ <--> Campus { delay = parent.coreDelay; } <--> core[i].port++;
        }
        for i=1..numValidators-1 {
            validator[i].port++ <--> Campus { delay = parent.coreDelay; } <--> core[(i-1) % numCore].port++;
        }
        for i=0..numEdge-1 {
            core[int(i / 2) % numCore].port++ <--> Campus { delay = parent.edgeDelay; } <--> edge[i].port++;
        }
        for i=0..int(numEdge / 2)-1 {
            edge[2*i].port++ <--> Campus { delay = parent.edgeDelay; } <--> edge[2*i+1].port++;
        }
        // Clinicians attach to the edge router of their own unit's building:
        // ICU (edge 0), Emergency (1), Radiology (2), Pharmacy and Oncology (3),
        // Surgery (4), front office (5).
        for k=0..numConsumers-1 {
            consumer[k].port++ <--> Access { delay = parent.accessDelay; datarate = parent.accessRate; } <--> edge[int(choose(k % 15, "0 0 0 1 1 2 2 3 4 3 3 4 4 5 5")) % numEdge].port++;
        }
        for k=0..numAttackers-1 {
            attacker[k].port++ <--> Access { delay = parent.accessDelay; datarate = parent.accessRate; } <--> edge[(k + 1) % numEdge].port++;
        }
}
